(function(){"use strict";

var Future = Meteor.npmRequire("fibers/future");
var wkhtmltopdf = Meteor.npmRequire("wkhtmltopdf");
var wkhtmltoimage = Meteor.npmRequire("wkhtmltoimage");
var puppeteer = Meteor.npmRequire("puppeteer");

var takeCabSnapShot = function (cab, cabID) {
  var future = new Future();
  (async () => {
    const browser = await puppeteer.launch({
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });

    const page = await browser.newPage();
    await page.setViewport({ height: 427, width: 341 });
    await page.goto(getWebHost() + "/cabonly/" + cabID);
    const watchDog = page.waitForFunction('window.status === "renderingDone"');
    await watchDog;
    await new Promise((resolve) => setTimeout(resolve, 2000));
    await page.screenshot({
      path: process.env.PWD + "/.uploads/cabonly/" + cab.renderedFile + ".jpg",
    });

    await browser.close();
  })().then((result) => {
    future.return({
      result: result,
    });
  });
  return future.wait();
};

var takeCabSnapShotOld = function (cab, cabID) {
  var future = new Future();
  wkhtmltoimage.generate(
    getWebHost() + "/cabonly/" + cabID,
    {
      width: 341,
      javascriptDelay: 5000,
      noStopSlowScripts: true,
      windowStatus: "renderingDone",
      output:
        process.env.PWD + "/.uploads/cabonly/" + cab.renderedFile + ".jpg",
    },
    function (error, result) {
      if (error) {
        future.return({
          error: error,
        });
      } else {
        future.return({
          result: result,
        });
      }
    }
  );
  return future.wait();
};

var takeFinalSnapShot = function (cab, cabID) {
  var future = new Future();
  (async () => {
    const browser = await puppeteer.launch({
      args: ["--no-sandbox", "--disable-setuid-sandbox"],
    });
    const page = await browser.newPage();
    await page.goto(getWebHost() + "/cab/" + cabID);
    const watchDog = page.waitForFunction('window.status === "renderingDone"');
    await watchDog;
    await new Promise((resolve) => setTimeout(resolve, 2000));
    await page.emulateMediaType("screen");
    await page.pdf({
      path: process.env.PWD + "/.uploads/cabpdfs/" + cab.renderedFile + ".pdf",
      format: "Letter",
      margin: { top: 0, bottom: 0, left: 0, right: 0 },
      printBackground: true,
    });
    await browser.close();
  })().then((result) => {
    future.return({
      result: result,
    });
  });
  return future.wait();
};

var takeFinalSnapShotOld = function (cab, cabID) {
  var future = new Future();
  wkhtmltopdf(
    getWebHost() + "/cab/" + cabID,
    {
      pageSize: "letter",
      marginBottom: "0mm",
      marginTop: "0mm",
      marginLeft: "0mm",
      marginRight: "0mm",
      noStopSlowScripts: true,
      javascriptDelay: 5000,
      ignore: [
        "content-type missing in HTTP POST, defaulting to application/x-www-form-urlencoded. Use QNetworkRequest::setHeader() to fix this problem.",
      ],
      windowStatus: "renderingDone",
      output:
        process.env.PWD + "/.uploads/cabpdfs/" + cab.renderedFile + ".pdf",
    },
    function (error, result) {
      if (error) {
        future.return({
          error: error,
        });
      } else {
        future.return({
          result: result,
        });
      }
    }
  );
  return future.wait();
};
var sendEmailToCustomer = function (cab) {
  Email.send({
    to: cab.email,
    from: "Eklunds.com Cab Designer <cabdesigner@eklunds.com>",
    subject: "Your Eklund's StreamLine Elevator Cab Design",
    html:
      "Thank you for using Eklund's StreamLine Cab" +
      " Design Studio!<br><br>" +
      "To view, save, or print the StreamLine cab design you created," +
      " please click <a href='" +
      getWebHost() +
      "/uploads/cabpdfs/" +
      cab.renderedFile +
      ".pdf'>here</a>.<br><br>" +
      "Your cab design has also been saved to your Eklund's Customer" +
      " Portal account. To access, please visit" +
      ' <a href='+ getWebHost() +'>'+ diaplayWebHostText +'</a>' +
      " and sign in to the Cab Design Studio.<br><br>" +
      "If you already requested an estimate we will be in touch" +
      " with you within the next few days. If you need to request" +
      " an estimate or have any questions, please contact" +
      ' <a href="mailto:sales@eklunds.com">sales@eklunds.com</a>. ' +
      "Be sure to include your rendering number" +
      " (located underneath the rendered cab) for reference.<br><br>" +
      "Thank you for your interest in Eklund's " +
      "and StreamLine!<br><br><br><br>" +
      "Scott Bachhuber | " +
      "National Sales & Marketing Manager<br>" +
      "Eklund's, Inc.<br>" +
      "P.O. Box 1566 | Grapevine, TX 76099<br>" +
      "p 817.949.2030 x112 | f 817.488.9158<br>" +
      "sbachhuber@eklunds.com | eklunds.com<br>",
  });
};

var sendEmailToAdmin = function (newRequestSubject, cab) {
  Email.send({
    to: "Eklund's <sbachhuber@eklunds.com>",
    from: "Eklunds.com Cab Designer <cabdesigner@eklunds.com>",
    subject: newRequestSubject,
    html:
      "A new completed cab" +
      " has been added to" +
      " your dashboard. <br><br>Click <a href='" +
      getWebHost() +
      "/uploads/cabpdfs/" +
      cab.renderedFile +
      ".pdf'>here</a>. to view the cab.<br><br>" +
      formatEklundsDate(cab.saved, "table") +
      "<br>" +
      "<b>Name:</b> " +
      cab.ownerName +
      " <br>" +
      "<b>Email:</b> " +
      cab.email +
      " <br>" +
      "<b>Phone:</b> " +
      cab.phone +
      " <br>" +
      "<b>Company:</b> " +
      cab.company +
      " <br>" +
      "<b>Project:</b> " +
      cab.project +
      " <br>" +
      "<b>Project City:</b> " +
      cab.projectCity +
      " <br>" +
      "<b>Project State:</b> " +
      cab.projectState +
      "<br>" +
      "<b>Installation Required:</b> " +
      cab.installationRequired +
      " <br>" +
      "<b># of Cabs:</b> " +
      cab.numberCabs +
      " <br>" +
      "<b>Budget Per Cab:</b> " +
      cab.cabBudget +
      " <br>" +
      "<b>Project Timeframe:</b> " +
      cab.projectTimeframe +
      "<br>" +
      "<b>Type:</b> " +
      cab.cabTypeName +
      "<br>" +
      "<b>Capacity:</b> " +
      cab.cabCapacity +
      " <br>" +
      "<b>Height:</b> " +
      cab.cabHeight +
      "<br>" +
      "<b>Notes:</b> " +
      cab.notes,
  });
};
var getWebHost = function () {
  var webHost = process.env.ROOT_URL;
  if (webHost.endsWith("/")) {
    webHost = webHost.substring(0, webHost.length - 1);
  }
  return webHost;
};

var rootUrl = getWebHost();

var displayHost = rootUrl
  .replace(/^https?:\/\//, "")
  .replace(/\/$/, "");

var diaplayWebHostText = displayHost.startsWith("www.")
  ? displayHost
  : "www." + displayHost;

Meteor.methods({
  sendErrorEmail: function (message) {
    check(message, Match.Any);
    Email.send({
      to: "brent.seibert@gmail.com",
      from: "error@eklunds.com",
      subject: "Error on Eklunds Site",
      text: message,
    });
  },
  removeCab: function (cabID, owner) {
    check(owner, Match.Any);
    check(cabID, Match.Any);
    if (isAdmin(Meteor.user()) || Meteor.user()._id === owner) {
      Cabs.remove(cabID);
      return "Removed Cab " + cabID;
    } else {
      return new Meteor.Error(
        403,
        "You don't have permissions to remove cabs."
      );
    }
  },
  saveCab: function (cab) {
    check(cab, Match.Any);
    if (Meteor.user()) {
      var tmpSettings = Settings.findOne();
      var latestCab = 1;
      if (tmpSettings.latestCab) {
        latestCab = tmpSettings.latestCab + 1;
      }

      cab.renderingNumber = latestCab;

      Settings.update(tmpSettings._id, {
        $set: {
          latestCab: latestCab,
        },
      });

      var newRequestSubject =
        "New StreamLine Elevator Cab Design from " + cab.ownerName;

      if (cab.estimate === "checked") {
        newRequestSubject =
          "**ESTIMATE REQUEST** New StreamLine Elevator Cab Design from " +
          cab.ownerName;
      }

      cab.renderedFile =
        "StreamLine-" +
        makeSlug(cab.cabName, true) +
        "-" +
        makeSlug(cab.project, true) +
        "-" +
        cab.renderingNumber +
        "-" +
        makeSlug(cab.company, true) +
        "-" +
        makeSlug(cab.ownerName, true) +
        "-" +
        formatEklundsDate(cab.saved, "forFile");

      var numSameFileName = Cabs.find({
        renderedFile: cab.renderedFile,
      }).count();

      while (numSameFileName > 0) {
        cab.renderedFile = cab.renderedFile + "-1";
        numSameFileName = Cabs.find({
          renderedFile: cab.renderedFile,
        }).count();
      }

      var cabID = Cabs.insert(cab);

      var cabResult = takeCabSnapShot(cab, cabID);

      var finalResult = takeFinalSnapShot(cab, cabID);

      if (!cabResult.error && !finalResult.error) {
        Meteor.setTimeout(function () {
          sendEmailToAdmin(newRequestSubject, cab);
        }, 0);
        Meteor.setTimeout(function () {
          sendEmailToCustomer(cab);
        }, 0);
        return {
          cabID: cabID,
          renderedFile: cab.renderedFile,
        };
      } else {
        Cabs.remove({
          _id: cabID,
        });
        Meteor.call(
          "sendErrorEmail",
          "Error Saving Cab from : " +
            cab.ownerName +
            "\n" +
            "cabResult: " +
            cabResult.error +
            "\n" +
            "finalResult" +
            finalResult.error +
            "\n" +
            "link: " +
            getWebHost() +
            "/cab/" +
            cabID
        );
        return new Meteor.Error(
          "save-error",
          "Error Saving Cab. An email has been sent to an administrator."
        );
      }
    } else {
      return new Meteor.Error(403, "You don't have permissions to save cabs.");
    }
  },
  setPassword: function (userId, pass) {
    check(userId, Match.Any);
    check(pass, Match.Any);
    if (
      (Meteor.user() && Meteor.user().profile.admin) ||
      Meteor.user()._id === userId
    ) {
      Accounts.setPassword(userId, pass);
    }
  },
  getEnvironment: function () {
    if (getWebHost() === "http://localhost:3000") {
      return "development";
    } else {
      return "production";
    }
  },
  addUser: function (options) {
    check(options, Match.Any);
    return Accounts.createUser(options);
  },
  signUpCustomer: function (options) {
    check(options, Match.Any);
    var subject = "Sign Up Form Submission";
    var text =
      "A new customer just signed up. Go to the dashboard" +
      " to set their region and activate their account.<br><br><br>";
    text = text + "Email : " + options.email + "<br>";

    if (options.profile.name) {
      text = text + "Name : " + options.profile.name + "<br>";
    }
    if (options.profile.company) {
      text = text + "Company : " + options.profile.company + "<br>";
    }
    if (options.profile.phone) {
      text = text + "Phone : " + options.profile.phone + "<br>";
    }
    if (options.username) {
      text = text + "Username : " + options.username + "<br>";
    }
    if (options.profile.address) {
      text = text + "Address : " + options.profile.address + "<br>";
    }
    if (options.profile.city) {
      text = text + "City : " + options.profile.city + "<br>";
    }
    if (options.profile.state) {
      text = text + "State : " + options.profile.state + "<br>";
    }
    if (options.profile.zip) {
      text = text + "Zip : " + options.profile.zip + "<br>";
    }
    if (options.profile.project) {
      text = text + "Project : " + options.profile.project + "<br>";
    }
    if (options.profile.howHear) {
      text =
        text +
        "How did you hear about us?  : " +
        options.profile.howHear +
        "<br>";
    }
    var newUid = Accounts.createUser(options);
    if (newUid) {
      Email.send({
        to: Settings.findOne({}).signUpEmailTo,
        from: Settings.findOne({}).signUpEmailFrom,
        subject: subject,
        html: text,
      });
      return true;
    }
  },
  welcomeEmail: function (user) {
    check(user, Match.Any);
    Accounts.sendEnrollmentEmail(user);
  }
});

(function () {
  Accounts.urls.resetPassword = function (token) {
    return Meteor.absoluteUrl("reset-password/" + token);
  };
  Accounts.urls.verifyEmail = function (token) {
    return Meteor.absoluteUrl("verify-email/" + token);
  };
  Accounts.urls.enrollAccount = function (token) {
    return Meteor.absoluteUrl("enroll-account/" + token);
  };
})();
Accounts.validateLoginAttempt(function (info) {
  if (!info.allowed) {
    throw new Meteor.Error(403, "Your username or password is incorrect.");
  }
  if (!info.user.profile.active) {
    throw new Meteor.Error(401, "Your profile is not active yet.");
  }
  return true;
});
Accounts.emailTemplates.siteName = "Eklunds.com";
if (Settings.find().count() > 0) {
  Accounts.emailTemplates.from = Settings.findOne({}).signUpEmailFrom;
}
Accounts.emailTemplates.resetPassword.subject = function (/*user*/) {
  return (
    "Request to reset your password for Eklund's " +
    "StreamLine Cab Design Studio"
  );
};
Accounts.emailTemplates.resetPassword.text = function (user, url) {
  return (
    "We received your request to reset your password for Eklund's " +
    "StreamLine Cab Design Studio.\n\nPlease click the link below and " +
    "follow the instructions.\n\n" +
    url +
    "\n\nPlease contact your Rep if you have any questions!\n\n\n\n" +
    "Scott Bachhuber | National Sales & Marketing Manager\n" +
    "Eklund's, Inc.\n" +
    "P.O. Box 1566 | Grapevine, TX 76099\n" +
    "p 817.949.2030 x112 | f 817.488.9158\n" +
    "sbachhuber@eklunds.com | eklunds.com\n"
  );
};
Accounts.emailTemplates.enrollAccount.subject = function (/*user*/) {
  return "Welcome! Action Required - Set Your Password";
};

Accounts.emailTemplates.enrollAccount.html = function (user, url) {
  return (
    "Thank you for registering for access to Eklund's StreamLine Cab Design Studio! Your account has been created.<br><br>" +
    '<b>***ACTION REQUIRED --- Please <a href="' +
    url +
    '">click here</a> to set your password.***</b><br><br>' +
    "Upon entering your password, your customer portal page will appear. Click the orange 'Access StreamLine Cab Design Studio' button to start designing!<br><br>" +
    "Please contact your Rep if you have any questions.<br>" +
    "We're looking forward to working with you!<br><br>" +
    "Thank you,<br><br>" +
    "Scott Bachhuber | National Sales & Marketing Manager<br>" +
    "Eklund's, Inc.<br>" +
    "P.O. Box 1566 | Grapevine, TX 76099<br>" +
    "p 817.949.2030 x112 | f 817.488.9158<br>" +
    '<a href="mailto:sbachhuber@eklunds.com">sbachhuber@eklunds.com</a> | <a href='+ getWebHost() +'>'+ diaplayWebHostText  +'</a><br><br>' +
    '<img src="http://www.eklunds.com/img/email-logo.png"> <img src="http://www.eklunds.com/img/email-bce.png">'
  );
};

// What's the meaning of this functions
var fs = Npm.require("fs");
WebApp.connectHandlers.use(function (req, res, next) {
  var re = /^\/uploads\/(.*)$/.exec(req.url);
  if (re !== null) {
    // Only handle URLs that start with /uploads/*
    var filePath = process.env.PWD + "/.uploads/" + decodeURIComponent(re[1]);
    
    if (!fs.statSync(filePath).isFile()) {
      filePath = process.env.PWD + "/.uploads/1x1.gif";
    }
    var data = fs.readFileSync(filePath, data);
    var fileExt = filePath.substring(filePath.lastIndexOf("."));
    if (fileExt === ".pdf") {
      res.writeHead(200, {
        "Content-Type": "document/pdf",
      });
    } else if (fileExt === ".png") {
      res.writeHead(200, {
        "Content-Type": "image/png",
      });
    } else {
      res.writeHead(200, {
        "Content-Type": "image",
      });
    }
    res.write(data);
    res.end();
  } else {
    // Other urls will have default behaviors
    next();
  }
});

}).call(this);
