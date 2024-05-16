const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const {Dropbox, DropboxAuth} = require('dropbox');
const fetch = require('isomorphic-fetch');
const util = require('util');
const exec = util.promisify(require('child_process').exec);

const refreshToken = process.env.REFRESH_TOKEN;
const clientId = process.env.APP_KEY;
const clientSecret = process.env.APP_SECRET;

async function refreshAccessToken() {
    const curlCommand = `curl -s -S https://api.dropbox.com/oauth2/token ` +
        `-d refresh_token=${refreshToken} ` +
        `-d grant_type=refresh_token ` +
        `-d client_id=${clientId} ` +
        `-d client_secret=${clientSecret}`;

    try {
        const { stdout, stderr } = await exec(curlCommand);
        if (stderr) {
            console.error(`stderr: ${stderr}`);
            throw new Error('Error refreshing access token');
        }
        const response = JSON.parse(stdout);
        console.log('Access Token:', response.access_token);
        return response.access_token;
    } catch (error) {
        console.error(`exec error: ${error}`);
        throw new Error('Failed to execute refresh token command');
    }
}

async function getDropboxClient() {
    try {
        const accessToken = await refreshAccessToken();
        console.log('Using access token:', accessToken);
        return new Dropbox({ accessToken, fetch });
    } catch (error) {
        console.error('Error getting Dropbox client:', error);
        throw error;
    }
}

let mongoDBConnectionString = process.env.MONGO_URL;

let Schema = mongoose.Schema;

let attachmentSchema = new Schema({
    FILENAME: String,
    DATA: Buffer, 
    DATE_UPLOADED: Date,
    PATH: String,
});

let journalEntrySchema = new Schema({
    FULL_NAME: String,
    USER_NAME: String,
    TITLE: String,
    BODY: String,
    LOCATION: String,
    LOCATION_RATING: String,
    DATE: String,
    IS_PRIVATE: Boolean,
    ATTACHMENT_IDS: [{ type: Schema.Types.ObjectId, ref: 'Attachment' }],
    LIKES: [{ type: String }],
    USER_ID: { type: Schema.Types.ObjectId, ref: 'User' },
    LATITUDE: Number,
    LONGITUDE: Number,
});

let userSchema = new Schema({
    FIRST_NAME: String,
    LAST_NAME: String,
    USER_NAME: {
        type: String,
        unique: true
    },
    USER_PASS: String,
    USER_PASS2: String,
    EMAIL_ADDRESS: String,
    DATE_CREATED: String,
    IS_ACTIVE: Boolean,
    TERMS: Boolean,
    SECURITY_QUESTION: String,
    SECURITY_ANSWER: String,
    PROFILE_IMAGE_ID: { type: Schema.Types.ObjectId, ref: 'Attachment' },
    JOURNAL_ENTRIES: [journalEntrySchema]
});

let threadSchema = new Schema({
    TITLE: String,
    BODY: String,
    USER_ID: { type: Schema.Types.ObjectId, ref: 'User' },
    DATE_CREATED: Date,
    LOCATION: String,
    ATTACHMENT_IDS: [{ type: Schema.Types.ObjectId, ref: 'Attachment' }],
    LATITUDE: Number,
    LONGITUDE: Number,
});

let replySchema = new Schema({
    BODY: String,
    USER_ID: { type: Schema.Types.ObjectId, ref: 'User' },
    DATE_CREATED: Date,
    THREAD_ID: { type: Schema.Types.ObjectId, ref: 'Thread' },
    ATTACHMENT_IDS: [{ type: Schema.Types.ObjectId, ref: 'Attachment' }]
});

let User;
let Attachment;
let Thread;
let Reply;

module.exports.connect = () =>{
    return new Promise(function (resolve, reject){
        let db = mongoose.createConnection(mongoDBConnectionString);
        console.log("Connected to Chronicle DB")
        db.on('error', err => {
            reject(err);
        })

        db.once('open', () => {
            User = db.model("users", userSchema);
            Attachment = db.model("attachments", attachmentSchema);
            Thread = db.model("threads", threadSchema);
            Reply = db.model("replies", replySchema);
            resolve();
        });
        
    });
};

module.exports.registerUser = (userData) => {
    console.log("Registering user (backend)")
    return new Promise(function (resolve, reject) {
        const specialCharRegex = /[!@#$%^&*?]/;
        if (userData.USER_PASS != userData.USER_PASS2) {
            reject("Passwords do not match");
        } else if (userData.USER_PASS.length < 8 || userData.USER_PASS.length > 16) {
            reject("Password must be between 8 and 16 characters");
        } else if (!specialCharRegex.test(userData.USER_PASS)) {
            reject("Password must contain at least one special character (!@#$%^&*?)");
        } else {
            // Hash both passwords for encryption; salted 10 times
            bcrypt.hash(userData.USER_PASS, 10)
                .then(hash1 => {
                    userData.USER_PASS = hash1;  // Update the first password with the hashed version

                    bcrypt.hash(userData.USER_PASS2, 10)
                        .then(hash2 => {
                            userData.USER_PASS2 = hash2;  // Update the second password with the hashed version

                            bcrypt.hash(userData.SECURITY_ANSWER, 10)
                            .then(hash3 => {
                                userData.SECURITY_ANSWER = hash3;  // Update the security answer with the hashed version

                            // Check if email already exists
                            User.findOne({ EMAIL_ADDRESS: userData.EMAIL_ADDRESS })
                                .then(user => {
                                    if (user) {
                                        reject("Email already exists");
                                    } else {
                                        let newUser = new User(userData);
                                        newUser.save()
                                            .then(() => {
                                                resolve(`User ${userData.USER_NAME} successfully registered`);
                                            })
                                            .catch(err => {
                                                if (err.code == 11000) {
                                                    reject("User Name already taken");
                                                } else {
                                                    reject(`There was an error creating the user: ${err}`);
                                                }
                                            });
                                    }
                                })
                                .catch(err => {
                                    reject(`There was an error checking the email: ${err}`);
                                });
                            })
                            .catch(err => reject(`Error hashing SECURITY_ANSWER: ${err}`));
                        })
                        .catch(err => reject(`Error hashing USER_PASS2: ${err}`));
                })
                .catch(err => reject(`Error hashing USER_PASS: ${err}`));
        }
    });
};

module.exports.checkUser = function (userData) {
    return new Promise(function (resolve, reject) {

        User.findOne({ USER_NAME: userData.userName })
            .exec()
            .then(user => {
                bcrypt.compare(userData.password, user.USER_PASS).then(res => {
                    if (res === true) {
                        resolve(user);
                    } else {
                        reject("Incorrect password for user " + userData.userName);
                    }
                });
            }).catch(err => {
                reject("Unable to find user " + userData.userName);
            });
    });
};

module.exports.checkUnAuthenticatedUser = (userData) => {
    return new Promise((resolve, reject) => {
        User.findOne({ USER_NAME: userData.userName })
            .exec()
            .then(user => {
                if (userData.email === user.EMAIL_ADDRESS) {
                    resolve(user);
                } else {
                    reject("Email not found for user " + userData.userName);
                }
            }).catch(err => {
                reject("Unable to find user " + userData.userName);
            });
    });
};

module.exports.checkRetrieveUser = (userData) => {
    console.log("Checking retrieve user for user " + userData.userName)
    return new Promise((resolve, reject) => {
        User.findOne({ USER_NAME: userData.userName })
            .exec()
            .then(user => {
                bcrypt.compare(userData.securityAnswer, user.SECURITY_ANSWER).then(res => {
                    if (res === true) {
                        resolve(user);
                    } else {
                        reject("Security Answer is Invalid");
                    }
                });
            }).catch(err => {
                reject("Unable to find user " + userData.userName);
            });
    });
};

module.exports.getUserById = (id) => {
    return new Promise((resolve, reject) => {
        User.findById(id)
        .exec()
        .then(user => {
            resolve(user);
        }).catch(err => {
            reject(`Unable to find user ${id}`);
        });
    });
};

module.exports.getUserByUsername = (username) => {
    return new Promise((resolve, reject) => {
        User.findOne({ USER_NAME: username }) 
            .exec()
            .then(user => {
                resolve(user);
            }).catch(err => {
                reject(`Error finding user: ${err}`);
            });
    });
};

//get username by user id
module.exports.getUsernameById = (id) => {
    return new Promise((resolve, reject) => {
        User.findById(id)
        .exec()
        .then(user => {
            resolve(user.USER_NAME);
        }).catch(err => {
            reject(`Unable to find user ${id}`);
        });
    });
};


module.exports.updateUser = (userId, userDataToUpdate, attachments) => {
    console.log(userDataToUpdate);
    console.log(attachments);

    let update_data = {
        LAST_NAME: userDataToUpdate.lastName,
        FIRST_NAME: userDataToUpdate.firstName,
        EMAIL_ADDRESS: userDataToUpdate.email,
    }
    return new Promise((resolve, reject) => {
        User.findById(userId).exec()
            .then(user => {
                if (!user) {
                    throw new Error("User not found");
                }

                if (attachments && attachments.length > 0) {
                    return Promise.all(attachments.map(attachment => {
                        const newAttachment = new Attachment({
                            FILENAME: attachment.originalname,
                            DATA: attachment.buffer,
                            DATE_UPLOADED: new Date(),
                        });
                        return newAttachment.save();
                    }))
                    .then(savedAttachments => {
                        const attachmentIds = savedAttachments.map(a => a._id);
                        if (!user.PROFILE_IMAGE_ID) {
                            user.PROFILE_IMAGE_ID = '';
                        }
                        console.log(attachmentIds);
                        user.PROFILE_IMAGE_ID = attachmentIds[0];
                        return user; 
                    });
                } else {
                    return user; 
                }
            })
            .then(user => {
                Object.keys(update_data).forEach(key => {
                    user[key] = update_data[key];
                });
                return user.save();
            })
            .then(updatedUser => resolve(updatedUser)) 
            .catch(err => reject(err));
    });
};


module.exports.deleteUser = (userId) => {
    return new Promise((resolve, reject) => {
        User.findByIdAndDelete(userId)
            .then(() => resolve(`User with ID ${userId} successfully deleted`))
            .catch(err => reject(`Error deleting user: ${err}`));
    });
};


module.exports.getAllUsersPublicJournalEntries = () => {
    return new Promise((resolve, reject) => {
        User.find({})
            .then(users => {
                let publicEntries = [];
                users.forEach(user => {
                    let userPublicEntries = user.JOURNAL_ENTRIES.filter(entry => entry.IS_PRIVATE === false);
                    publicEntries.push(...userPublicEntries);
                });
                resolve(publicEntries);
            })
            .catch(err => {
                reject(`Error finding users: ${err}`);
            });
    });
};

module.exports.getAllJournalEntriesById = (userId) => {
    return new Promise((resolve, reject) => {
        User.findById(userId)
            .then(user => {
                if (!user) {
                    reject("User not found");
                } else {
                    resolve(user.JOURNAL_ENTRIES);
                }
            }).catch(err => {
                reject(`Error finding user: ${err}`);
            });
    });
};

module.exports.addJournalEntry = async (userId, journalEntryData) => {
    console.log("THIS IS THE DATA",journalEntryData);
    return new Promise(async (resolve, reject) => {
        try {

            const user = await User.findById(userId);
            if (!user) {
                return reject("User not found");
            }

            let attachmentIds = [];
            if (journalEntryData.attachments && journalEntryData.attachments.length > 0) {
                const attachments = await Promise.all(journalEntryData.attachments.map(async (attachment) => {
                    const newAttachment = new Attachment({
                        FILENAME: attachment.FILENAME,
                        DATA: attachment.DATA,
                        DATE_UPLOADED: new Date(),
                        PATH: attachment.PATH,
                    });
                    await newAttachment.save();
                    return newAttachment._id;
                }));
                attachmentIds = attachments;
            }


            const newJournalEntry = {
                FULL_NAME: `${user.FIRST_NAME} ${user.LAST_NAME}`,
                USER_NAME: `${user.USER_NAME}`,
                TITLE: journalEntryData.title,
                BODY: journalEntryData.text,
                LOCATION: journalEntryData.location,
                LOCATION_RATING: journalEntryData.location_rating,
                DATE: new Date().toISOString(),
                IS_PRIVATE: journalEntryData.is_private,
                ATTACHMENT_IDS: attachmentIds, 
                USER_ID: userId,
                LATITUDE: journalEntryData.latitude,
                LONGITUDE: journalEntryData.longitude,
            };
            console.log("New JOURNAL ENTRY DATA: ",newJournalEntry);

            user.JOURNAL_ENTRIES.push(newJournalEntry);

            await user.save();

            resolve("Journal entry added successfully with attachments");
        } catch (err) {
            reject(`Error adding journal entry: ${err}`);
        }
    });
};




// Get journal entry by id
// Search through all User objects in the database to find journal post with the given id

module.exports.getJournalEntryById = (journalEntryId) => {
    return new Promise((resolve, reject) => {
        User.find({})
            .then(users => {
                let journalEntry;
                users.forEach(user => {
                    user.JOURNAL_ENTRIES.forEach(entry => {
                        if (entry._id == journalEntryId) {
                            journalEntry = entry;
                        }
                    });
                });
                if (journalEntry) {
                    resolve(journalEntry);
                } else {
                    reject(`Journal entry with ID ${journalEntryId} not found`);
                }
            })
            .catch(err => {
                reject(`Error finding journal entry: ${err}`);
            });
    });
}

module.exports.getImageDataById = async (id) => {
    if (!mongoose.Types.ObjectId.isValid(id)) {
        throw new Error('Invalid ID format');
    }

    console.log('============ Image ID: ============', id);

    const attachment = await Attachment.findById(id);
    if (!attachment) {
        throw new Error('File not found');
    }
    if (attachment.PATH && attachment.PATH.startsWith("https")) {
        console.log(attachment.PATH);
        return attachment.PATH;
    }
    const base64Data = attachment.DATA.toString('base64');
    const imgSrc = `data:image/jpeg;base64,${base64Data}`;
    return imgSrc;
}



module.exports.updateJournalEntry = (journalEntryId, journalEntryData) => {
    console.log('Entry Data:', journalEntryData);
    return new Promise(async (resolve, reject) => {
        try {
            const users = await User.find({});
            let userWithEntry;
            for (const user of users) {
                const index = user.JOURNAL_ENTRIES.findIndex(entry => entry._id.toString() === journalEntryId);
                if (index !== -1) {

                    oldAttachmentIds = [...user.JOURNAL_ENTRIES[index].ATTACHMENT_IDS];

                    let attachmentIds = [];
                    if (journalEntryData.attachments && journalEntryData.attachments.length > 0) {
                        const attachments = await Promise.all(journalEntryData.attachments.map(async (attachment) => {
                            const newAttachment = new Attachment({
                                FILENAME: attachment.FILENAME,
                                DATA: attachment.DATA,
                                DATE_UPLOADED: new Date(),
                            });
                            await newAttachment.save();
                            return newAttachment._id;
                        }));
                        attachmentIds = attachments;
                    }

                    user.JOURNAL_ENTRIES[index].TITLE = journalEntryData.title;
                    user.JOURNAL_ENTRIES[index].LOCATION = journalEntryData.location;
                    user.JOURNAL_ENTRIES[index].LOCATION_RATING = journalEntryData.locationRating;
                    user.JOURNAL_ENTRIES[index].BODY = journalEntryData.text;
                    user.JOURNAL_ENTRIES[index].IS_PRIVATE = journalEntryData.is_private;
                    user.JOURNAL_ENTRIES[index].LOCATION_RATING = journalEntryData.location_rating;
                    user.JOURNAL_ENTRIES[index].LATITUDE = journalEntryData.latitude;
                    user.JOURNAL_ENTRIES[index].LONGITUDE = journalEntryData.longitude;

                    console.log('rating:', journalEntryData.location_rating)

                    if (attachmentIds.length > 0) {
                        user.JOURNAL_ENTRIES[index].ATTACHMENT_IDS = attachmentIds;
                    }

                    userWithEntry = user;
                }
            }
            if (userWithEntry) {
                await userWithEntry.save();

                if (oldAttachmentIds.length > 0 && attachmentIds.length > 0) {
                    await Attachment.deleteMany({_id: { $in: oldAttachmentIds }});
                }

                resolve(`Journal entry with ID ${journalEntryId} updated successfully`);
            } else {
                reject(`Journal entry with ID ${journalEntryId} not found`);
            }
        } catch (err) {
            reject(`Error updating journal entry: ${err}`);
        }
    });
}


module.exports.deleteJournalEntry = (journalEntryId) => {
    return new Promise((resolve, reject) => {
        User.find({})
            .then(users => {
                let userWithEntry;
                let attachmentsToDelete = [];

                users.forEach(user => {
                    user.JOURNAL_ENTRIES.forEach((entry, index) => {
                        if (entry._id.toString() === journalEntryId) {
                            attachmentsToDelete = entry.ATTACHMENT_IDS;
                            user.JOURNAL_ENTRIES.splice(index, 1);
                            userWithEntry = user;
                        }
                    });
                });

                if (userWithEntry) {
                    Attachment.deleteMany({_id: { $in: attachmentsToDelete }})
                        .then(() => {
                            return userWithEntry.save();
                        })
                        .then(() => {
                            resolve({ message: `Journal entry with ID ${journalEntryId} and its attachments deleted successfully` });
                        })
                        .catch(err => {
                            reject({ message: `Error during operation: ${err}` });
                        });
                } else {
                    reject({ message: `Journal entry with ID ${journalEntryId} not found` });
                }
            })
            .catch(err => {
                reject({ message: `Error finding users: ${err}` });
            });
    });
};


//setJournalEntryPrivacy(entryId, privacy)
module.exports.setJournalEntryPrivacy = (journalEntryId, privacy) => {
    return new Promise((resolve, reject) => {
        User.find({})
            .then(users => {
                let userWithEntry;
                users.forEach(user => {
                    user.JOURNAL_ENTRIES.forEach(entry => {
                        if (entry._id == journalEntryId) {
                            entry.IS_PRIVATE = privacy;
                            userWithEntry = user;
                        }
                    });
                });
                if (userWithEntry) {
                    userWithEntry.save()
                        .then(() => {
                            resolve(`Journal entry with ID ${journalEntryId} privacy updated successfully`);
                        })
                        .catch(err => {
                            reject(`Error updating journal entry privacy: ${err}`);
                        });
                } else {
                    reject(`Journal entry with ID ${journalEntryId} not found`);
                }
            })
            .catch(err => {
                reject(`Error finding journal entry: ${err}`);
            });
    });
}

//Add User Id string to JournalEntry Likes Array
//addUserToLikes(entryId, userId)
//search all journal entries across all users to find the entry with the given id, then add the user id to that journal entry likes array

module.exports.addUserToLikes = (journalEntryId, userId) => {
    return new Promise((resolve, reject) => {
        User.find({})
            .then(users => {
                let userWithEntry;
                users.forEach(user => {
                    user.JOURNAL_ENTRIES.forEach(entry => {
                        if (entry._id == journalEntryId) {
                            entry.LIKES.push(userId);
                            userWithEntry = user;
                        }
                    });
                });
                if (userWithEntry) {
                    userWithEntry.save()
                        .then(() => {
                            resolve(`User added to likes for journal entry with ID ${journalEntryId} successfully`);
                        })
                        .catch(err => {
                            reject(`Error adding user to likes for journal entry: ${err}`);
                        });
                } else {
                    reject(`Journal entry with ID ${journalEntryId} not found`);
                }
            })
            .catch(err => {
                reject(`Error finding journal entry: ${err}`);
            });
    });
};

//Add User Id string to JournalEntry Likes Array
//removeUserFromLikes(entryId, userId)
//search all journal entries across all users to find the entry with the given id, then remove the user id in that journal entry likes array

module.exports.removeUserFromLikes = (journalEntryId, userId) => {
    return new Promise((resolve, reject) => {
        User.find({})
            .then(users => {
                let userWithEntry;
                users.forEach(user => {
                    user.JOURNAL_ENTRIES.forEach(entry => {
                        if (entry._id == journalEntryId) {
                            let index = entry.LIKES.indexOf(userId);
                            if (index > -1) {
                                entry.LIKES.splice(index, 1);
                            }
                            userWithEntry = user;
                        }
                    });
                });
                if (userWithEntry) {
                    userWithEntry.save()
                        .then(() => {
                            resolve(`User removed from likes for journal entry with ID ${journalEntryId} successfully`);
                        })
                        .catch(err => {
                            reject(`Error removing user from likes for journal entry: ${err}`);
                        });
                } else {
                    reject(`Journal entry with ID ${journalEntryId} not found`);
                }
            })
            .catch(err => {
                reject(`Error finding journal entry: ${err}`);
            });
    });
};

module.exports.uploadVideo = async (fileObject, dropboxPath) => {
    try {
        if (!fileObject || !fileObject.buffer) {
            throw new Error('Invalid file object. Missing "buffer".');
        }

        const dbx = await getDropboxClient();
        const fileBuffer = fileObject.buffer;

        await dbx.filesUpload({ 
            path: dropboxPath,
            contents: fileBuffer,
            mode: 'overwrite', 
        });

        try {

            const sharedLink = await dbx.sharingCreateSharedLinkWithSettings({
                path: dropboxPath,
            });
            console.log('Link: ', sharedLink.result.url);
            return sharedLink.result.url; 
        } catch (error) {
            if (error.error.error_summary.startsWith('shared_link_already_exists/')) {
                const links = await dbx.sharingListSharedLinks({
                    path: dropboxPath,
                });
                const existingLink = links.result.links[0].url; 
                console.log('Existing Link: ', existingLink);
                return existingLink; 
            } else {
                throw error; 
            }
        }
    } catch (error) {
        console.error('Error uploading video:', error);
        throw error;
    }
};

//changePassword
module.exports.changePassword = (userData) => {
    console.log("Inside Changing password (backend) function");   
    console.log("userData.oldPasswordInput: ", userData.oldPasswordInput);
    console.log("userData.updatedPasswordData.PASSWORD: ",userData.updatedPasswordData.PASSWORD);
    console.log("userData.updatedPasswordData.CONFIRM_PASSWORD: ",userData.updatedPasswordData.CONFIRM_PASSWORD);
    console.log("userData.updatedPasswordData.USER_NAME: ", userData.updatedPasswordData.USER_NAME);

    return new Promise((resolve, reject) => {
        User.findOne({ USER_NAME: userData.updatedPasswordData.USER_NAME })
            .then(user => {
                if (user) {
                    console.log("User found");
                    console.log("user.USER_NAME: ", userData.updatedPasswordData.USER_NAME);
                    console.log("user.USER_PASS: ", user.USER_PASS);
                    console.log("user.USER_PASS2: ", user.USER_PASS2);
                    console.log("userData.PASSWORD: ", userData.updatedPasswordData.PASSWORD);
                    console.log("userData.updatedPasswordData.CONFIRM_PASSWORD: ", userData.updatedPasswordData.CONFIRM_PASSWORD);
                    bcrypt.compare(userData.oldPasswordInput, user.USER_PASS)
                    .then(res => {
                        if (res === true) {
                            bcrypt.hash(userData.updatedPasswordData.PASSWORD, 10)
                            .then(hash1 => {
                                userData.updatedPasswordData.PASSWORD = hash1;  // Update the first password with the hashed version

                                bcrypt.hash(userData.updatedPasswordData.CONFIRM_PASSWORD, 10)
                                .then(hash2 => {
                                    userData.updatedPasswordData.CONFIRM_PASSWORD = hash2;  // Update the second password with the hashed version
                                    
                                    console.log("Password matched");
                                    user.USER_PASS = userData.updatedPasswordData.PASSWORD;
                                    user.USER_PASS2 = userData.updatedPasswordData.CONFIRM_PASSWORD;
                                    user.save()
                                        .then(() => {
                                            resolve(`Password changed successfully`);
                                        })
                                        .catch(err => {
                                            reject(`There was an error changing the password: ${err}`);
                                        });
                                })
                                .catch(err => reject(`Error hashing USER_PASS2: ${err}`));
                            })
                            .catch(err => reject(`Error hashing USER_PASS: ${err}`));
                        } else {
                            reject(`Incorrect Old Password for user ${userData.updatedPasswordData.USER_NAME}`);
                        }
                    });
                } else {
                    reject(`User not found`);
                }
            })
            .catch(err => {
                reject(`There was an error changing the password: ${err}`);
            });
    });
};
                
//createPassword
module.exports.createPassword = (userData) => {
    console.log("Inside Create New password (backend) function");   

    return new Promise((resolve, reject) => {
        User.findOne({ USER_NAME: userData.updatedPasswordData.USER_NAME })
            .then(user => {
                if (user) {
                    console.log("User found");
                    console.log("user.USER_NAME: ", userData.updatedPasswordData.USER_NAME);
                    console.log("user.USER_PASS: ", user.USER_PASS);
                    console.log("user.USER_PASS2: ", user.USER_PASS2);
                    console.log("userData.updatedPasswordData.PASSWORD: ", userData.updatedPasswordData.PASSWORD);
                    console.log("userData.updatedPasswordData.CONFIRM_PASSWORD: ", userData.updatedPasswordData.CONFIRM_PASSWORD);
                   
                     
                            bcrypt.hash(userData.updatedPasswordData.PASSWORD, 10)
                            .then(hash1 => {
                                userData.updatedPasswordData.PASSWORD = hash1;  // Update the first password with the hashed version

                                bcrypt.hash(userData.updatedPasswordData.CONFIRM_PASSWORD, 10)
                                .then(hash2 => {
                                    userData.updatedPasswordData.CONFIRM_PASSWORD = hash2;  // Update the second password with the hashed version
                                    
                                    console.log("Changing Password");
                                    console.log("userData.updatedPasswordData.PASSWORD: ", userData.updatedPasswordData.PASSWORD);
                                    console.log("userData.updatedPasswordData.CONFIRM_PASSWORD: ", userData.updatedPasswordData.CONFIRM_PASSWORD);          
                                    user.USER_PASS = userData.updatedPasswordData.PASSWORD;
                                    user.USER_PASS2 = userData.updatedPasswordData.CONFIRM_PASSWORD;
                                    user.save()
                                        .then(() => {
                                            resolve(`New Password created successfully`);
                                        })
                                        .catch(err => {
                                            reject(`There was an error creating the new password: ${err}`);
                                        });
                                })
                                .catch(err => reject(`Error hashing USER_PASS2: ${err}`));
                            })
                            .catch(err => reject(`Error hashing USER_PASS: ${err}`));
                         

                    } else {
                        reject(`User not found`);
                    }
            })
            .catch(err => {
                reject(`There was an error creating the new password: ${err}`);
            });
    });
};

module.exports.addThread = async (userId, threadData) => {
    return new Promise(async (resolve, reject) => {
        try {
            const user = await User.findById(userId);
            if (!user) {
                reject("User not found");
                return;
            }

            let attachmentIds = [];
            if (threadData.attachments && threadData.attachments.length > 0) {
                const attachments = await Promise.all(threadData.attachments.map(async (attachment) => {
                    const newAttachment = new Attachment({
                        FILENAME: attachment.FILENAME,
                        DATA: attachment.DATA,
                        DATE_UPLOADED: new Date(),
                        PATH: attachment.PATH,
                    });
                    return newAttachment.save();
                }));
                attachmentIds = attachments.map(attachment => attachment._id);
            }

            const newThread = new Thread({
                TITLE: threadData.title,
                BODY: threadData.text,
                DATE_CREATED: new Date(),
                ATTACHMENT_IDS: attachmentIds,
                USER_ID: userId,
                LATITUDE: threadData.latitude,
                LONGITUDE: threadData.longitude,
                LOCATION: threadData.location
            });

            const savedThread = await newThread.save();
            resolve(savedThread);

        } catch (err) {
            console.error("Error creating new thread:", err);
            reject(`Error creating new thread: ${err}`);
        }
    });
};

module.exports.getAllThreads = () => {
    console.log("Get All Threads Called")
    return new Promise((resolve, reject) => {
        Thread.find({})
            .then(threads => {
                resolve(threads);
            })
            .catch(err => {
                reject(`Error finding threads: ${err}`);
            });
    });
};

module.exports.getRepliesByThreadId = (threadId) => {
    return new Promise((resolve, reject) => {
        if (!mongoose.Types.ObjectId.isValid(threadId)) {
            reject('Invalid thread ID format');
            return;
        }

        Reply.find({ THREAD_ID: threadId })
            .then(replies => {
                resolve(replies);
            })
            .catch(err => {
                console.error("Error finding replies by thread ID:", err);
                reject(`Error finding replies for thread ID ${threadId}: ${err}`);
            });
    });
};

module.exports.addReply = async (replyData) => {
    return new Promise(async (resolve, reject) => {
        try {
            const newReply = new Reply({
                BODY: replyData.body,
                USER_ID: replyData.userId,
                THREAD_ID: replyData.threadId,
                DATE_CREATED: new Date(), 
            });

            const savedReply = await newReply.save();

            resolve(savedReply);
        } catch (err) {
            console.error("Error adding new reply:", err);
            reject(`Error adding new reply: ${err}`);
        }
    });
};

// 'GET' thread by thread Id
module.exports.getThreadById = (threadId) => {
    return new Promise((resolve, reject) => {
        Thread.findById(threadId)
            .then(thread => {
                if (thread) {
                    resolve(thread);
                } else {
                    reject(`Thread with ID ${threadId} not found`);
                }
            })
            .catch(err => {
                reject(`Error finding thread: ${err}`);
            });
    });
};

// 'DELETE'reply by reply Id
module.exports.deleteReply = (replyId) => {
    console.log("INSIDE Deleting reply with ID: ", replyId);
    return new Promise((resolve, reject) => {
        Reply.findByIdAndDelete(replyId)
            .then(() => {
                resolve(`Reply with ID ${replyId} successfully deleted`);
                console.log("Reply Deleted");
            })
            .catch(err => {
                reject(`Error deleting reply: ${err}`);
                console.log("Reply Not Deleted");
            }); 
    }
    );
}

// 'DELETE' thread by thread Id
module.exports.deleteThread = (threadId) => {
    console.log("INSIDE Deleting thread with ID: ", threadId);
    return new Promise((resolve, reject) => {
        Thread.findByIdAndDelete(threadId)
            .then(() => {
                resolve(`Thread with ID ${threadId} successfully deleted`);
                console.log("Thread Deleted");
            })
            .catch(err => {
                reject(`Error deleting thread: ${err}`);
                console.log("Thread Not Deleted");
            });
    });
};

// 'UPDATE' reply by reply Id and replyContent which is reply body
module.exports.updateReply = (replyId, content) => {
    return new Promise((resolve, reject) => {
        Reply.findById(replyId)
            .then(reply => {
                if (reply) {
                    console.log("reply.BODY: ", reply.BODY);
                    console.log("replyContent: ", content);
                    reply.BODY = content;
                    return reply.save();
                } else {
                    reject(`Reply with ID ${replyId} not found`);
                }
            })
            .then(() => {
                resolve(`Reply with ID ${replyId} updated successfully`);
            })
            .catch(err => {
                reject(`Error updating reply: ${err}`);
            });
    });
}