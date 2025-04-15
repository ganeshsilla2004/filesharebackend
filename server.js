
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const { v4: uuidv4 } = require('uuid');
const {
  S3Client,
  PutObjectCommand,
  DeleteObjectCommand,
} = require('@aws-sdk/client-s3');
const {
  DynamoDBClient,
  PutItemCommand,
  ScanCommand,
  DeleteItemCommand,
  QueryCommand,
} = require('@aws-sdk/client-dynamodb');

dotenv.config();

const app = express();
const port = process.env.PORT || 5001;

// Ensure uploads directory exists
if (!fs.existsSync('./uploads')) {
  fs.mkdirSync('./uploads');
}

app.use(express.json());
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE'],
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// AWS S3 client
const s3 = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

// AWS DynamoDB client
const dynamoClient = new DynamoDBClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

// Multer setup
const storage = multer.diskStorage({
  destination: './uploads',
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});
const upload = multer({ storage });

// Cognito JWKS for JWT validation
const jwks = jwksClient({
  jwksUri: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}/.well-known/jwks.json`,
  cache: true,
  cacheMaxAge: 86400000, // 1 day cache
});

// Middleware: authenticate JWT from Cognito
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  
  if (!token) {
    console.log('Token missing');
    return res.status(401).json({ error: 'Token missing' });
  }

  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) {
      console.log('Could not decode token');
      return res.status(401).json({ error: 'Invalid token format' });
    }

    const kid = decoded?.header?.kid;
    if (!kid) {
      console.log('No KID in token header');
      return res.status(401).json({ error: 'Invalid token header' });
    }

    jwks.getSigningKey(kid, (err, key) => {
      if (err) {
        console.log('JWKS error:', err);
        return res.status(401).json({ error: 'JWKS error' });
      }

      const signingKey = key.getPublicKey();

      jwt.verify(
        token, 
        signingKey, 
        {
          algorithms: ['RS256'],
          issuer: `https://cognito-idp.${process.env.AWS_REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`,
        }, 
        (err, payload) => {
          if (err) {
            console.log('Token verification error:', err);
            return res.status(401).json({ error: 'Invalid token' });
          }
          
          // Extract email from the payload
          const email = payload.email || payload['cognito:username'];
          if (!email) {
            return res.status(401).json({ error: 'Email not found in token' });
          }
          
          req.user = { ...payload, email };
          next();
        }
      );
    });
  } catch (error) {
    console.log('Authentication error:', error);
    return res.status(401).json({ error: 'Authentication failed' });
  }
}

// Debug endpoint to check authentication
app.get('/api/auth-check', authenticateToken, (req, res) => {
  res.status(200).json({ 
    message: 'Authentication successful',
    user: {
      email: req.user.email,
      sub: req.user.sub
    }
  });
});

// Route: Upload file
app.post('/api/upload', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    if (!req.file || !req.user?.email) {
      return res.status(400).json({ error: 'Missing file or user email' });
    }

    const fileContent = fs.readFileSync(req.file.path);
    const allowedMimeTypes = ['image/png', 'image/jpeg', 'application/pdf'];

    if (!allowedMimeTypes.includes(req.file.mimetype)) {
      fs.unlinkSync(req.file.path);
      return res.status(400).json({ error: 'Invalid file type' });
    }

    const fileId = uuidv4();
    const filename = req.file.filename;
    const fileUrl = `https://${process.env.S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${filename}`;

    // Upload to S3
    await s3.send(new PutObjectCommand({
      Bucket: process.env.S3_BUCKET,
      Key: filename,
      Body: fileContent,
      ContentType: req.file.mimetype,
    }));

    // Remove local temp file
    fs.unlinkSync(req.file.path);

    // Store metadata in DynamoDB
    const metadata = {
      TableName: process.env.DYNAMODB_TABLE,
      Item: {
        fileId: { S: fileId },
        userEmail: { S: req.user.email },
        fileName: { S: req.file.originalname || 'unknown' },
        fileUrl: { S: fileUrl },
        fileSize: { N: `${req.file.size || 0}` },
        fileType: { S: req.file.mimetype || 'application/octet-stream' },
        uploadTime: { S: new Date().toISOString() },
        // Store the S3 key for future deletion
        s3Key: { S: filename },
      },
    };

    await dynamoClient.send(new PutItemCommand(metadata));

    res.status(200).json({ message: 'File uploaded', url: fileUrl });
  } catch (error) {
    console.error('Upload Error:', error);
    res.status(500).json({ error: 'Upload failed', details: error.message });
  }
});

// Route: Get current user's files
app.get('/api/my-files', authenticateToken, async (req, res) => {
  const userEmail = req.user.email;

  const params = {
    TableName: process.env.DYNAMODB_TABLE,
    FilterExpression: '#userEmail = :userEmail',
    ExpressionAttributeNames: {
      '#userEmail': 'userEmail',
    },
    ExpressionAttributeValues: {
      ':userEmail': { S: userEmail },
    },
  };

  try {
    const data = await dynamoClient.send(new ScanCommand(params));

    const items = data.Items.map(item => ({
      fileId: item.fileId.S,
      fileName: item.fileName.S,
      uploadTime: item.uploadTime.S,
      fileUrl: item.fileUrl.S,
      fileSize: item.fileSize.N,
      fileType: item.fileType.S,
      s3Key: item.s3Key?.S,
    }));

    res.status(200).json(items);
  } catch (error) {
    console.error('Fetch my files error:', error);
    res.status(500).json({ error: 'Failed to fetch files', details: error.message });
  }
});

// New route: Delete file
app.delete('/api/files/:fileId', authenticateToken, async (req, res) => {
  const { fileId } = req.params;
  const userEmail = req.user.email;

  console.log(`Attempting to delete file with ID: ${fileId} for user: ${userEmail}`);
  
  try {
    // First, get the file details to check ownership and get S3 key
    const scanParams = {
      TableName: process.env.DYNAMODB_TABLE,
      FilterExpression: 'fileId = :fileId AND userEmail = :userEmail',
      ExpressionAttributeValues: {
        ':fileId': { S: fileId },
        ':userEmail': { S: userEmail }
      }
    };

    console.log('Scan params:', JSON.stringify(scanParams, null, 2));

    const scanResult = await dynamoClient.send(new ScanCommand(scanParams));
    console.log('Scan result:', JSON.stringify(scanResult, null, 2));
    
    if (!scanResult.Items || scanResult.Items.length === 0) {
      console.log('File not found or user not authorized');
      return res.status(404).json({ error: 'File not found or not authorized to delete' });
    }

    const fileItem = scanResult.Items[0];
    
    // Get the filename from fileUrl if s3Key is not available
    let s3Key = fileItem.s3Key?.S;
    if (!s3Key && fileItem.fileUrl?.S) {
      // Extract the filename from the URL
      const urlParts = fileItem.fileUrl.S.split('/');
      s3Key = urlParts[urlParts.length - 1];
    }
    
    console.log('S3 Key:', s3Key);

    // Delete from S3 if we have a key
    if (s3Key) {
      try {
        console.log(`Deleting from S3 bucket: ${process.env.S3_BUCKET}, key: ${s3Key}`);
        await s3.send(new DeleteObjectCommand({
          Bucket: process.env.S3_BUCKET,
          Key: s3Key
        }));
        console.log('S3 delete successful');
      } catch (s3Error) {
        console.error('S3 delete error:', s3Error);
        // Continue with DynamoDB deletion even if S3 fails
      }
    }

    // Delete from DynamoDB using a DeleteItemCommand with all primary key attributes
    try {
      // Extract all attributes to build a complete key
      const deleteParams = {
        TableName: process.env.DYNAMODB_TABLE,
        Key: {}
      };
      
      // From the logs, we need to determine what the primary key of your table is
      // It's likely either just fileId, or a composite of fileId and something else
      
      // Try with fileId
      deleteParams.Key.fileId = { S: fileId };
      
      // If your table uses a hash key and range key (composite primary key)
      // Uncomment and adjust one of these:
      // deleteParams.Key.userEmail = { S: userEmail };
      // OR
      // deleteParams.Key.uploadTime = { S: fileItem.uploadTime.S };
      
      console.log('Delete params:', JSON.stringify(deleteParams, null, 2));
      
      // Try to delete with just fileId
      try {
        await dynamoClient.send(new DeleteItemCommand(deleteParams));
        console.log('DynamoDB delete successful with fileId key');
      } catch (err) {
        // If that fails, try with userEmail as the sort key
        if (err.name === 'ValidationException') {
          console.log('First delete attempt failed, trying with composite key fileId + userEmail');
          deleteParams.Key.userEmail = { S: userEmail };
          
          try {
            await dynamoClient.send(new DeleteItemCommand(deleteParams));
            console.log('DynamoDB delete successful with fileId + userEmail composite key');
          } catch (err2) {
            // If that also fails, we need to check what the actual primary key structure is
            console.error('Second delete attempt also failed:', err2);
            throw err2;
          }
        } else {
          throw err;
        }
      }
    } catch (dynamoError) {
      console.error('DynamoDB delete error:', dynamoError);
      return res.status(500).json({ 
        error: 'Failed to delete file record', 
        details: dynamoError.message,
        message: 'The DynamoDB table structure might be different than expected. Check your table\'s primary key configuration.'
      });
    }

    console.log('File deleted successfully');
    res.status(200).json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error('Delete file error:', error);
    res.status(500).json({ error: 'Failed to delete file', details: error.message });
  }
});

app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});