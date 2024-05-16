// Import express and create an express object:
const express = require('express');
const app = express();

// Import CORS middleware to allow requests from different origins.
// This is particularly important for web applications that might 
// be served from a different domain than the API server.
const cors = require('cors');
// Import 'dotenv' module to load variables from a '.env' file
const dotenv = require('dotenv');
dotenv.config()
// Import user-service2 module
const userService = require("./user-service.js")

const jwt = require('jsonwebtoken');
const passport = require('passport');
const passportJWT = require('passport-jwt');

const multer = require('multer');
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });



const HTTP_PORT = process.env.PORT || 8080;

// JSON Web Token Setup
let ExtractJwt = passportJWT.ExtractJwt;
let JwtStrategy = passportJWT.Strategy;

// Configure its options
let jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('jwt'),
  secretOrKey: process.env.JWT_SECRET,
};

let strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {
  console.log('payload received', jwt_payload);

  if (jwt_payload) {
 
    next(null, {
      _id: jwt_payload._id,
      FIRST_NAME: jwt_payload.FIRST_NAME,
      LAST_NAME: jwt_payload.LAST_NAME,
      USER_NAME: jwt_payload.USER_NAME,
      USER_PASS: jwt_payload.USER_PASS,
      USER_PASS2: jwt_payload.USER_PASS2,
      EMAIL_ADDRESS: jwt_payload.EMAIL_ADDRESS,
      DATE_CREATED: jwt_payload.DATE_CREATED,
      IS_ACTIVE: jwt_payload.IS_ACTIVE,
      TERMS: jwt_payload.TERMS,
      SECURITY_QUESTION: jwt_payload.SECURITY_QUESTION,
      SECURITY_ANSWER: jwt_payload.SECURITY_ANSWER,
      JOURNAL_ENTRIES: jwt_payload.JOURNAL_ENTRIES
    });
  } else {
    next(null, false);
  }
});


// Responsible for parsing incoming requests with JSON payloads, globally.
app.use(express.json());
// Responsible for allowing requests from different origins, globally.
app.use(cors());

passport.use(strategy);
app.use(passport.initialize());


// 'POST' Register User Route
app.post("/api/user/register", (req,res) => {
    userService.registerUser(req.body)
    .then((msg) => {
        res.json({ "message": msg });
    }).catch((msg) => {
        res.status(422).json({ "message": msg });
    });
});

// 'POST' Login User Route
app.post("/api/user/login", (req, res) => {
    userService.checkUser(req.body)
    .then((user) => {
        const payload = { _id: user._id, USER_NAME: user.USER_NAME };
        const secret = process.env.JWT_SECRET; 
        const options = { expiresIn: '1h' }; 

        const token = jwt.sign(payload, secret, options);

        res.json({ 
            message: "Login successful", 
            id: user._id, 
            token: token 
        });
    }).catch(msg => {
        res.status(422).json({ message: msg });
    });
});

// 'POST' Check Unauthenticated User Route
// Vaibhav Branch
app.post("/api/user/checkUnAuthenticatedUser", (req, res) => {
    console.log(req.body);
    userService.checkUnAuthenticatedUser(req.body)
    .then((user) => {
        const payload = { _id: user._id, USER_NAME: user.USER_NAME };
        const secret = process.env.JWT_SECRET; 
        const options = { expiresIn: '1h' }; 

        const token = jwt.sign(payload, secret, options);

        res.json({ 
            message: "Authentication successful", 
            id: user._id, 
            token: token 
        });
    }).catch(msg => {
        res.status(422).json({ message: msg });
    });
});

// 'POST' retrieveUser Route
// Vaibhav Branch
app.post("/api/user/retrieveUser", (req, res) => {
    console.log(req.body);
    userService.checkRetrieveUser(req.body)
    .then((user) => {
        const payload = { _id: user._id, USER_NAME: user.USER_NAME };
        const secret = process.env.JWT_SECRET; 
        const options = { expiresIn: '1h' }; 

        const token = jwt.sign(payload, secret, options);

        res.json({ 
            message: "Authentication successful", 
            id: user._id, 
            token: token 
        });
    }).catch(msg => {
        res.status(422).json({ message: msg });
    });
});

// 'GET' User Route
app.get("/api/user/:id", (req, res) => {
    userService.getUserById(req.params.id)
    .then(data => {
        res.json(data);
    }).catch(msg => {
        res.status(422).json({ error: msg });
    })

});

app.get("/api/user/username/:username", (req, res) => {
    const username = req.params.username; 
    userService.getUserByUsername(username)
        .then(data => {
            res.json(data);
        })
        .catch(msg => {
            res.status(422).json({ error: msg });
        });
});

//get username by user id
app.get("/api/user/usernameById/:id", (req, res) => {
    userService.getUsernameById(req.params.id)
        .then(data => {
            res.json(data);
        })
        .catch(msg => {
            res.status(422).json({ error: msg });
        });
});

app.put("/api/user/:id", upload.single('avatar'), (req, res) => {
    const userId = req.params.id;

    let attachments = [];
    if (req.file) {
        attachments.push({
            originalname: req.file.originalname,
            buffer: req.file.buffer,
            DATE_UPLOADED: new Date(),
        });
    }

    console.log(req.body);

    let userDataToUpdate = {...req.body};

    userService.updateUser(userId, userDataToUpdate, attachments)
    .then(data => {
        console.log('Data', data);
        res.json({ message: "User updated successfully", data });
    }).catch(msg => {
        res.status(422).json({ error: msg });
    });
});


app.delete("/api/user/:id", (req, res) => {
    const userId = req.params.id;

    userService.deleteUser(userId)
        .then(msg => {
            res.json({ message: msg });
        })
        .catch(err => {
            res.status(500).json({ error: err });
        });
});


//getAllUsersPublicJournalEntries 

app.get("/api/journal-entries", (req, res) => {
    userService.getAllUsersPublicJournalEntries()
        .then(data => {
            res.json(data);
        })
        .catch(err => {
            res.status(500).json({ error: err });
        });
});

//getAllJournalEntriesById

app.get("/api/journal-entries/:id", (req, res) => {
    userService.getAllJournalEntriesById(req.params.id)
        .then(data => {
            res.json(data);
        })
        .catch(err => {
            res.status(500).json({ error: err });
        });
});

//addJournalentry

app.post('/api/journal-entries', upload.single('attachments'), async (req, res) => {
    const userId = req.body.userId;
    let journalEntry = {
        ...req.body,
        attachments: [], 
    };

    if (req.file) {
        if (req.file.mimetype.startsWith('video/')) {
            const dropboxPath = `/${req.file.originalname}`;
            console.log('PATH: ', dropboxPath);
            
            try {
                const inp_file = req.file; 
                const fileUploaded = await userService.uploadVideo(inp_file, dropboxPath);
                
                if (fileUploaded) {
                    console.log('Video uploaded to Dropbox successfully', fileUploaded);
                    journalEntry.attachments.push({
                        FILENAME: req.file.originalname,
                        DATA: '',
                        PATH: fileUploaded,
                        DATE_UPLOADED: new Date(),
                    });
                } else {
                    return res.status(500).send({message: 'Failed to upload video'});
                }
            } catch (error) {
                console.error('Error uploading video:', error);
                return res.status(500).send({message: 'Error uploading video', error});
            }
        } else {
            journalEntry.attachments.push({
                FILENAME: req.file.originalname,
                DATA: req.file.buffer,
                DATE_UPLOADED: new Date(),
                PATH: '',
            });
        }
    }

    userService.addJournalEntry(userId, journalEntry)
        .then(() => res.status(200).send({'message': 'Journal entry added successfully'}))
        .catch(err => res.status(500).send(err));
});


//updateJournalEntry

app.put('/api/journal-entries/entry/:entryId', upload.array('attachments'), (req, res) => {
    const entryId = req.params.entryId;
    console.log("req.body: ", req.body);
    console.log("entryId: ", entryId);

    let journalEntry = {
        ...req.body,
    };

    //update the incoming journal entry with the new data and attachments if any, keep the date same as it was before
    if (req.files && req.files.length > 0) {
        journalEntry.attachments = req.files.map(file => ({
            FILENAME: file.originalname,
            DATA: file.buffer,
            DATE_UPLOADED: new Date()
        }));
    }
    console.log("calling updateJournalEntry", journalEntry);
    userService.updateJournalEntry(entryId, journalEntry) 
        .then(() => res.status(200).send('Journal entry updated successfully'))
        .catch(err => res.status(500).send(err));
    
    // const entryId = req.params.entryId;
});

//deleteJournalEntry

app.delete('/api/journal-entries/entry/:entryId', (req, res) => {
    console.log("entryId: ", req.params.entryId);
    const id  = req.params.entryId;
    userService.deleteJournalEntry(id)
        .then(response => res.json(response))
        .catch(error => res.status(500).json(error));
});

//getJournalEntryById

app.get('/api/journal-entries/entry/:entryId', (req, res) => {
    userService.getJournalEntryById(req.params.entryId)
        .then(data => {
            res.json(data);
        })
        .catch(err => {
            res.status(500).json({ error: err });
        });
});

app.get('/api/images/:id', async (req, res) => {
    try {
        const id = req.params.id;
        const imgSrc = await userService.getImageDataById(id);
        res.send(imgSrc);
    } catch (err) {
        console.error(err.message);
        if (err.message === 'Invalid ID format' || err.message === 'File not found') {
            res.status(404).send(err.message);
        } else {
            res.status(500).send('Server error');
        }
    }
});

//setJournalEntryPrivacy(entryId, privacy)

app.put('/api/journal-entries/entry/:entryId/privacy', (
    req, res) => {
    userService.setJournalEntryPrivacy(req.params.entryId, req.body.privacy)
        .then(() => res.status(200).send('Journal entry privacy updated successfully'))
        .catch(err => res.status(500).send(err));
});

//changePassword

app.put('/api/user/change-password/:id', (req, res) => {
    console.log("Calling Change password (backend) function");   
    console.log("req.body: ", req.body);
    userService.changePassword(req.body)
        .then(() => res.status(200).send('Password changed successfully'))
        .catch(err => res.status(500).send(err));
});

//createPassword

app.put('/api/user/create-password/:id', (req, res) => {
    console.log("Calling create password (backend) function");   
    console.log("req.body: ", req.body);
    userService.createPassword(req.body)
        .then(() => res.status(200).send('New Password created successfully'))
        .catch(err => res.status(500).send(err));
});


//Add User Id string to JournalEntry Likes Array
//addUserToLikes(entryId, userId)
// /journal-entries/entry/${entryId}/likes/${userId}

app.put('/api/journal-entries/entry/:entryId/likes/:userId', (req, res) => {
    userService.addUserToLikes(req.params.entryId, req.params.userId)
        .then(() => res.status(200).send('User added to likes successfully'))
        .catch(err => res.status(500).send(err));
});


//Add User Id string to JournalEntry Likes Array
//removeUserFromLikes(entryId, userId)
// /journal-entries/entry/${entryId}/likes/${userId}

app.delete('/api/journal-entries/entry/:entryId/likes/:userId', (req, res) => {
    userService.removeUserFromLikes(req.params.entryId, req.params.userId)
        .then(() => res.status(200).send('User removed from likes successfully'))
        .catch(err => res.status(500).send(err));
});

app.post('/api/forum', upload.single('attachments'), async (req, res) => {
    const userId = req.body.userId;
    let threadData = {
        ...req.body,
        attachments: [], 
    };

    if (req.file) {
        if (req.file.mimetype.startsWith('video/')) {
            const dropboxPath = `/${req.file.originalname}`;
            console.log('PATH: ', dropboxPath);
            
            try {
                const inp_file = req.file; 
                const fileUploaded = await userService.uploadVideo(inp_file, dropboxPath);
                
                if (fileUploaded) {
                    console.log('Video uploaded to Dropbox successfully', fileUploaded);
                    threadData.attachments.push({
                        FILENAME: req.file.originalname,
                        DATA: '',
                        PATH: fileUploaded,
                        DATE_UPLOADED: new Date(),
                    });
                } else {
                    return res.status(500).send({message: 'Failed to upload video'});
                }
            } catch (error) {
                console.error('Error uploading video:', error);
                return res.status(500).send({message: 'Error uploading video', error});
            }
        } else {
            threadData.attachments.push({
                FILENAME: req.file.originalname,
                DATA: req.file.buffer,
                DATE_UPLOADED: new Date(),
                PATH: '',
            });
        }
    }

    userService.addThread(userId, threadData)
        .then(() => res.status(200).send({'message': 'Thread Created successfully'}))
        .catch(err => res.status(500).send(err));
});

app.get("/api/forum", (req, res) => {
    userService.getAllThreads()
        .then(data => {
            res.json(data);
        })
        .catch(err => {
            res.status(500).json({ error: err });
        });
});

app.get('/api/replies/:threadId', async (req, res) => {
    const { threadId } = req.params;
    try {
        const replies = await userService.getRepliesByThreadId(threadId);
        res.json(replies);
    } catch (error) {
        console.error("Failed to fetch replies:", error);
        res.status(500).json({ message: error.message });
    }
});

app.post('/api/replies/add', async (req, res) => {
    try {
        const replyData = {
            body: req.body.content,
            userId: req.body.userId,
            threadId: req.body.threadId,
        };

        const savedReply = await userService.addReply(replyData);

        res.status(201).json(savedReply);
    } catch (error) {
        console.error("Failed to add reply:", error);
        res.status(500).json({ message: error.message });
    }
});

// 'GET' thread by thread Id
app.get('/api/forum/:threadId', (req, res) => {
    userService.getThreadById(req.params.threadId)
        .then(data => {
            res.json(data);
        })
        .catch(err => {
            res.status(500).json({ error: err });
        });
});

// 'DELETE' reply by reply Id
app.delete('/api/replies/:replyId', (req, res) => {
    console.log("calling deleteReply with replyId: ", req.params.replyId);
    userService.deleteReply(req.params.replyId)
        .then(() => res.status(200).json({ message: 'Reply deleted successfully' }))
        .catch(err => res.status(500).send(err));
});

// 'DELETE' thread by thread Id
app.delete('/api/forum/:threadId', (req, res) => {
    console.log("calling deleteThread with threadId: ", req.params.threadId);
    userService.deleteThread(req.params.threadId)
        .then(() => res.status(200).json({ message: 'Thread deleted successfully' }))
        .catch(err => res.status(500).send(err));
});

// 'PUT' reply by reply Id and replyContent which is reply body
app.put('/api/replies/:replyId', (req, res) => {
    console.log("calling updateReply with replyId: ", req.params.replyId, " and replyContent: ", req.body.content);
    userService.updateReply(req.params.replyId, req.body.content)
        .then(() => res.status(200).json({ message: 'Reply updated successfully' }))
        .catch(err => res.status(500).send(err));
});

userService.connect()
.then(() => {
    app.listen(HTTP_PORT, () => {
        console.log("API listening on: " + HTTP_PORT)
    });
})
.catch((err) => {
    console.log(`unable to start the server: ${err}`);
    process.exit();
})
