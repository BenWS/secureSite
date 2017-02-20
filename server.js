var express = require('express')
var app = express();
var pug = require('pug');
var bodyParser = require('body-parser');
var multer = require('multer'); // v1.0.5
var upload = multer(); // for parsing multipart/form-data
var mongo = require('mongodb').MongoClient;
var bCrypt = require("./app/bcrypt/bCrypt");

app.use(bodyParser.json()); // for parsing application/json
app.use(bodyParser.urlencoded({ extended: true })); // for parsing application/x-www-form-urlencoded

//set view directory
app.set("views", "./views");
app.set("view engine", "pug");

app.get('/newuser', (req, res) => {
    res.render('newUser', {message:""});
})

app.get('/userAuthentication',  (req, res) => {
    res.render('userAuth');
})

app.get('/newPassword', (req, res) => {
    //by default, provide empty message string
    res.render('newPassword', {message:""});
})

app.post('/newUserPost', upload.array(), (req, res) => {
    console.log(req.body.username)
    console.log(req.body.password)
    console.log(req.body.confirmPassword)
    
    //first check whether all of the fields contain data
    if (req.body.username === "" || req.body.password == "" || req.body.confirmPassword == "") {
        res.render('newUser', {message:"*Please submit data for all fields"})
    } else if (req.body.password !== req.body.confirmPassword) {
        res.render('newUser', {message:"*Password fields must match - please resubmit"})
    } else {

        //generate salt
        var numberOfRounds = 10;
	    var salt = bCrypt.genSaltSync(numberOfRounds);
	    
	    //run salt and chosen password through hashing algoithm to encrypt password
	    var encryptedPassword = bCrypt.hashSync(req.body.password, salt);
	    
	    //database connection
	    mongo.connect('mongodb://localhost:27017/testDatabase', function (err, db) {
	        
	        //check to see if database returns error
	        if(err) {
    		    console.log(err);
	        }
	        
	        //set usersColl equal to the 'users' collection in the database 
	        var usersColl = db.collection('users');
	        var user = req.body.username
	        
	        //check to see whether username already exists
            usersColl.find({user:user}).toArray(function(err, doc) {
                //check to see whether submitted user exists
                if (doc.length > 0) {
                    res.render('newUser', {message:"*Username/password combination already exists"});
                } else {
                    usersColl.insert(
            		    {user:req.body.username, //insert username field from POST body
            		    password:encryptedPassword,
            		    salt:salt}, 
            		    //return data handling
                		(err, data) => {
                			console.log(JSON.stringify(data))
                			if (err) {
                				console.log(err);
                			}
                			res.end('Thanks for your submission')
                		});
                }
            })
	        
	        
	    })
    }
})

app.post('/newPasswordPost', upload.array(), (req, res) => {
    console.log(req.body.username)
    console.log(req.body.newPassword)
    console.log(req.body.oldPassword)
    
    if (req.body.username === "" || req.body.newPassword === "" || req.body.oldPassword === "") {
        res.render('newPassword', {message:"*Please submit data for all fields"})
    } else if (req.body.newPassword === req.body.oldPassword) {
        res.render('newPassword', {message:"*New password cannot match old - please resubmit"})
    } else {
        mongo.connect('mongodb://localhost:27017/testDatabase', function (err, db) {
            //declare database we're connecting to
        	var usersColl = db.collection('users');
        	var salt;
        	
        	//get data from POST body
        	var user = req.body.username;
        	var newPassword = req.body.newPassword;
        	var oldPassword = req.body.oldPassword;
        	
        	//get salt by querying username
        	usersColl.find({user:user}).toArray(function(err, doc) {
        	    //if results are returned
        	    if (doc.length == 0) {
        	        res.render('newPassword', {message:"Username or password not found"})
        	    } else {
        	        salt = doc[0].salt;
        	    }
        	    
        	    //run old password, new password, through encryption algorithm along with salt
        	    var oldEncryptedPassword = bCrypt.hashSync(oldPassword, salt);
        	    var newEncryptedPassword = bCrypt.hashSync(newPassword, salt);
        	    
        	    //query user with Old Password
        	    usersColl.find({user:user, password:oldEncryptedPassword}).toArray(function(err, doc) {
        	        if(doc.length == 0) {
        	            res.render('newPassword', {message:"Username or password not found"});
        	        } else {
        	            //insert into database
        	            usersColl.updateOne({user:user, password:oldEncryptedPassword}, {$set:{password:newEncryptedPassword}});
        	            res.end('Password updated! Thanks for your submission.')
        	        }
        	    });
        	});
        })
    }
})

app.post('/userAuthPost', upload.array(), (req, res) => {
    console.log(req.body.username)
    console.log(req.body.password)
    
    if(req.body.username === "" || req.body.password === "") {
        res.render('userAuth',  {message:"*Please submit data for all fields"});
    } else {
        mongo.connect('mongodb://localhost:27017/testDatabase', function (err, db) {
            //declare database we're connecting to
        	var usersColl = db.collection('users');
        	var salt;
        	
        	//get data from POST body
        	var user = req.body.username;
        	var password = req.body.password;
        	
        	usersColl.find({user:user}).toArray(function(err, doc) {
        	    
        	    //if results are returned
        	    if (doc.length == 0) {
    	            res.render('userAuth', {message:"*Username or password not found"});
        	    } else {
        	        //first get user and salt
            	    salt = doc[0].salt;
            	    
            	    //next run provide password and salt through hashing algorithm
            	    var encryptedPassword = bCrypt.hashSync(password, salt);
            	    
            	    usersColl.find({user:user, password:encryptedPassword}).toArray(function(err, doc) {
            	        
            	        if (doc.length == 0) {
        	            res.render('userAuth', {message:"*Username or password not found"});
            	        } else {
            	            //check returned document
                	        console.log(doc[0]);
                	        //close database connection
                    		db.close();
                    		//send response
                    		res.end('Thanks for your submission');
            	        }
            	    });
        	    }
        	});
        })
    }
})


app.listen(8080);