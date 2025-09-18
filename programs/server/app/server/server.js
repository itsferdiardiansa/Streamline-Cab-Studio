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
      ' <a href="http://eklunds.com">www.eklunds.com</a>' +
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
  uploadProfileFile: function (file, options) {
    check(file, Match.Any);
    check(options, Match.Any);
    var base = process.env.PWD;
    file.save(base + "/.uploads/profiles", options);
  },
  uploadGalleryFile: function (file, options) {
    check(file, Match.Any);
    check(options, Match.Any);
    var base = process.env.PWD;
    file.save(base + "/.uploads/galleries", options);
  },
  uploadNewsFile: function (file, options) {
    check(file, Match.Any);
    check(options, Match.Any);
    var base = process.env.PWD;
    file.save(base + "/.uploads/news", options);
  },
  uploadTestimonialFile: function (file, options) {
    check(file, Match.Any);
    check(options, Match.Any);
    var base = process.env.PWD;
    file.save(base + "/.uploads/testimonials", options);
  },
  uploadCareersFile: function (file, options) {
    check(file, Match.Any);
    check(options, Match.Any);
    var base = process.env.PWD;
    file.save(base + "/.uploads/careers", options);
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
        // text: text
        html: text,
      });
      return true;
    }
  },
  welcomeEmail: function (user) {
    check(user, Match.Any);
    //if (Meteor.user.profile.admin) {
    Accounts.sendEnrollmentEmail(user);
    //}
  },
  sendContactEmail: function (options) {
    check(options, Match.Any);
    var subject = "Contact Form Submission";
    var text = "Email : " + options.contactEmail + "<br>";
    if (options.subject === "generalInquiry") {
      subject = "[General Inquiry]";
    } else if (options.subject === "proposalRequest") {
      subject = "[Proposal Request]";
    } else if (options.subject === "cabshieldInquiry") {
      subject = "[CabShield Website Inquiry]";
    }
    if (options.contactName) {
      text = text + "Name : " + options.contactName + "<br>";
    }
    if (options.contactCompany) {
      text = text + "Company : " + options.contactCompany + "<br>";
    }
    if (options.contactState) {
      text = text + "State : " + options.contactState + "<br>";
    }
    if (options.contactZip) {
      text = text + "Zip : " + options.contactZip + "<br>";
    }
    if (options.contactAddress) {
      text = text + "Address : " + options.contactAddress + "<br>";
    }
    if (options.contactCity) {
      text = text + "City : " + options.contactCity + "<br>";
    }
    if (options.contactPhone) {
      text = text + "Phone : " + options.contactPhone + "<br>";
    }
    if (options.contactRepresentative) {
      text =
        text + "Representative : " + options.contactRepresentative + "<br>";
    }
    if (options.contactContactOther) {
      text = text + "Contact (Other) : " + options.contactContactOther + "<br>";
    }
    if (options.cabProjectName) {
      text = text + "Project Name : " + options.cabProjectName + "<br>";
    }
    if (options.cabWallPanels) {
      text = text + "Wall Panels : " + options.cabWallPanels + "<br>";
    }
    if (options.cabProjectDate) {
      text = text + "Project Date : " + options.cabProjectDate + "<br>";
    }
    if (options.cabFrontReturns) {
      text = text + "Front Returns : " + options.cabFrontReturns + "<br>";
    }
    if (options.cabProjectType) {
      text = text + "Project Type : " + options.cabProjectType + "<br>";
    }
    if (options.cabDoorStyle) {
      text = text + "Door Style : " + options.cabDoorStyle + "<br>";
    }
    if (options.cabDimension) {
      text = text + "Dimensions : " + options.cabDimension + "<br>";
    }
    if (options.cabDoorSize) {
      text = text + "Door Size : " + options.cabDoorSize + "<br>";
    }
    if (options.cabSize) {
      text = text + "Cab Size : " + options.cabSize + "<br>";
    }
    if (options.cabCeilingFrame) {
      text = text + "Ceiling & Frame : " + options.cabCeilingFrame + "<br>";
    }
    if (options.cabLinearFeet) {
      text = text + "Linear Feet : " + options.cabLinearFeet + "<br>";
    }
    if (options.cabFan) {
      text = text + "Fan : " + options.cabFan + "<br>";
    }
    if (options.cabShell) {
      text = text + "Shell : " + options.cabShell + "<br>";
    }
    if (options.cabSill) {
      text = text + "Sill : " + options.cabSill + "<br>";
    }
    if (options.cabTop) {
      text = text + "Car Top : " + options.cabTop + "<br>";
    }
    if (options.cabHandrails) {
      text = text + "Handrails : " + options.cabHandrails + "<br>";
    }
    if (options.howHear) {
      text = text + "How did you hear about us?  : " + options.howHear + "<br>";
    }
    if (options.formComments) {
      text = text + "Comments : " + options.formComments + "<br>";
    }

    Email.send({
      to: Settings.findOne({}).contactEmailTo,
      from: Settings.findOne({}).contactEmailFrom,
      subject: subject,
      html: text,
    });
  },
  sendEmployeeFormEmail: function (options) {
    check(options, Match.Any);

    var toEmail = options.toEmail ? options.toEmail : "hr@eklunds.com";
    var subject = options.subject
      ? options.subject
      : "Employee Form Submission";
    var text = "";

    var fieldNames = options.fieldNames;
    var values = options.values;
    for (var i = 0; i < fieldNames.length; i++) {
      var fieldName = fieldNames[i];
      var value = values[i];
      text = text + fieldName + (fieldName ? ": " : "") + value + "<br>";
    }

    console.log("Employee Form email: " + text);
    Email.send({
      to: toEmail,
      from: "no-reply@eklunds.com",
      subject: subject,
      html: text,
    });
  },
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
    '<a href="mailto:sbachhuber@eklunds.com">sbachhuber@eklunds.com</a> | <a href="http://eklunds.com">eklunds.com</a><br><br>' +
    '<img src="http://www.eklunds.com/img/email-logo.png"> <img src="http://www.eklunds.com/img/email-bce.png">'
  );
};

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
  } else if (req.url.startsWith("/cab-data")) {
    var token = req.query && req.query.token;
    var user = token
      ? Meteor.users.findOne({
          "services.resume.loginTokens.hashedToken":
            Accounts._hashLoginToken(token),
        })
      : undefined;
    if (typeof user === "undefined" || !isAdmin(user)) {
      next();
      return;
    }
    var xlsx = Meteor.npmRequire("excel4node");
    var wbOpts = {
      // allowInterrupt: true,
    };
    var wb = new xlsx.WorkBook(wbOpts);
    var wsOpts = {
      view: {
        zoom: 100,
      },
      fitToPage: {
        fitToHeight: 100,
        orientation: "landscape",
      },
    };
    var ws = wb.WorkSheet("CABS", wsOpts);
    ws.Cell(1, 1).String("Date");
    ws.Cell(1, 2).String("ID");
    ws.Cell(1, 3).String("Name");
    ws.Cell(1, 4).String("Company");
    ws.Cell(1, 5).String("Phone");
    ws.Cell(1, 6).String("Email");
    ws.Cell(1, 7).String("Region");
    ws.Cell(1, 8).String("Address");
    ws.Cell(1, 9).String("Project City");
    ws.Cell(1, 10).String("Project State");
    ws.Cell(1, 11).String("Installation Required");
    ws.Cell(1, 12).String("# of Cabs");
    ws.Cell(1, 13).String("Budget per cab");
    ws.Cell(1, 14).String("Project Timeframe");
    ws.Cell(1, 15).String("Capacity");
    ws.Cell(1, 16).String("Height");
    ws.Cell(1, 17).String("Type");
    ws.Cell(1, 18).String("Cab Name");
    ws.Cell(1, 19).String("Estimate");
    ws.Cell(1, 20).String("Notes");
    ws.Cell(1, 21).String("Link to PDF Rendering");

    var cabs = Cabs.find(
      {},
      {
        sort: {
          renderingNumber: -1,
        },
      }
    ).fetch();

    var j = 2;
    cabs.forEach(function (cab) {
      var customer = Meteor.users.findOne({
        _id: cab.owner,
        // 'profile.customer': true,
      });

      if (customer) {
        ws.Cell(j, 1).Date(cab.created);
        ws.Cell(j, 2).Number(Number(cab.renderingNumber));
        ws.Cell(j, 3).String(customer.profile.name || "");
        ws.Cell(j, 4).String(customer.profile.company || "");
        ws.Cell(j, 5).String(customer.profile.phone || "");
        ws.Cell(j, 6).String(customer.emails[0].address || "");
        ws.Cell(j, 7).String(customer.profile.region || "");
        ws.Cell(j, 8).String(customer.profile.address || "");
        ws.Cell(j, 9).String(cab.projectCity || "");
        ws.Cell(j, 10).String(cab.projectState || "");
        ws.Cell(j, 11).String(cab.installationRequired || "");
        ws.Cell(j, 12).String(cab.numberCabs || "");
        ws.Cell(j, 13).String(cab.cabBudget || "");
        ws.Cell(j, 14).String(cab.projectTimeframe || "");
        ws.Cell(j, 15).String(cab.cabCapacity || "");
        ws.Cell(j, 16).String(cab.cabHeight || "");
        ws.Cell(j, 17).String(cab.cabTypeName || "");
        ws.Cell(j, 18).String(cab.cabName || "");
        if (cab.estimate) {
          ws.Cell(j, 19).String("Yes");
        }
        ws.Cell(j, 20).String(cab.notes);
        ws.Cell(j, 21).Link(
          "http://eklunds.com/uploads/cabpdfs/" + cab.renderedFile + ".pdf"
        );
        j++;
      }
    });

    wb.write("Cabs Data.xlsx", res);
  } else if (req.url.startsWith("/customer-data")) {
    var token = req.query && req.query.token;
    var user = token
      ? Meteor.users.findOne({
          "services.resume.loginTokens.hashedToken":
            Accounts._hashLoginToken(token),
        })
      : undefined;
    if (typeof user === "undefined" || !isAdmin(user)) {
      next();
      return;
    }
    var xlsx = Meteor.npmRequire("excel4node");
    var wbOpts = {
      // allowInterrupt: true,
    };
    var wb = new xlsx.WorkBook(wbOpts);
    var wsOpts = {
      view: {
        zoom: 100,
      },
      fitToPage: {
        fitToHeight: 100,
        orientation: "landscape",
      },
    };

    var singleCustomer = req.query && req.query.id;

    var ws = wb.WorkSheet("Customers", wsOpts);
    ws.Cell(1, 1).String("Created");
    ws.Cell(1, 2).String("Name");
    ws.Cell(1, 3).String("Company");
    ws.Cell(1, 4).String("Phone");
    ws.Cell(1, 5).String("Email");
    ws.Cell(1, 6).String("Region");
    ws.Cell(1, 7).String("Address");
    ws.Cell(1, 8).String("City");
    ws.Cell(1, 9).String("State");
    ws.Cell(1, 10).String("Zip");
    ws.Cell(1, 11).String("Welcome Email");
    ws.Cell(1, 12).String("Active");
    ws.Cell(1, 13).String("# of Cabs Designed");

    var query = {
      "profile.customer": true,
    };
    if (singleCustomer) {
      query._id = req.query.id;
    }
    var customers = Meteor.users
      .find(query, {
        sort: {
          createdAt: -1,
        },
      })
      .fetch();

    var j = 2;
    customers.forEach(function (customer) {
      if (customer) {
        var cabsCursor = Cabs.find(
          { owner: customer._id },
          {
            sort: {
              renderingNumber: -1,
            },
          }
        );
        var numCabs = cabsCursor.count();
        ws.Cell(j, 1).Date(customer.createdAt);
        ws.Cell(j, 2).String(customer.profile.name);
        ws.Cell(j, 3).String(customer.profile.company);
        ws.Cell(j, 4).String(customer.profile.phone);
        ws.Cell(j, 5).String(customer.emails[0].address);
        ws.Cell(j, 6).String(
          customer.profile.region ? customer.profile.region : ""
        );
        ws.Cell(j, 7).String(customer.profile.address);
        ws.Cell(j, 8).String(customer.profile.city);
        ws.Cell(j, 9).String(customer.profile.state);
        ws.Cell(j, 10).String(customer.profile.zip);
        ws.Cell(j, 11).String(customer.profile.welcomeSent ? "X" : "");
        ws.Cell(j, 12).String(customer.profile.active ? "X" : "");
        ws.Cell(j, 13).Number(Number(numCabs));
        if (singleCustomer && numCabs > 0) {
          var cabs = cabsCursor.fetch();
          var k = j + 4;
          ws.Cell(k - 1, 1).String("Cabs");
          ws.Cell(k, 1).String("Date");
          ws.Cell(k, 2).String("ID");
          ws.Cell(k, 3).String("Project City");
          ws.Cell(k, 4).String("Project State");
          ws.Cell(k, 5).String("Installation Required");
          ws.Cell(k, 6).String("# of Cabs");
          ws.Cell(k, 7).String("Budget per cab");
          ws.Cell(k, 8).String("Project Timeframe");
          ws.Cell(k, 9).String("Capacity");
          ws.Cell(k, 10).String("Height");
          ws.Cell(k, 11).String("Type");
          ws.Cell(k, 12).String("Cab Name");
          ws.Cell(k, 13).String("Estimate");
          ws.Cell(k, 14).String("Notes");
          ws.Cell(k, 15).String("Link to PDF Rendering");

          var m = k + 1;
          cabs.forEach(function (cab) {
            ws.Cell(m, 1).Date(cab.created);
            ws.Cell(m, 2).Number(Number(cab.renderingNumber));
            ws.Cell(m, 3).String(cab.projectCity);
            ws.Cell(m, 4).String(cab.projectState);
            ws.Cell(m, 5).String(cab.installationRequired);
            ws.Cell(m, 6).String(cab.numberCabs);
            ws.Cell(m, 7).String(cab.cabBudget);
            ws.Cell(m, 8).String(cab.projectTimeframe);
            ws.Cell(m, 9).String(cab.cabCapacity);
            ws.Cell(m, 10).String(cab.cabHeight);
            ws.Cell(m, 11).String(cab.cabTypeName);
            ws.Cell(m, 12).String(cab.cabName);
            if (cab.estimate) {
              ws.Cell(m, 13).String("Yes");
            }
            ws.Cell(m, 14).String(cab.notes);
            ws.Cell(m, 15).Link(
              "http://eklunds.com/uploads/cabpdfs/" + cab.renderedFile + ".pdf"
            );
            m++;
          });
        }
        j++;
      }
    });

    wb.write("Customer Data.xlsx", res);
  } else if (req.url.startsWith("/inquiry-data")) {
    var token = req.query && req.query.token;
    var user = token
      ? Meteor.users.findOne({
          "services.resume.loginTokens.hashedToken":
            Accounts._hashLoginToken(token),
        })
      : undefined;
    if (typeof user === "undefined" || !isAdmin(user)) {
      next();
      return;
    }
    var xlsx = Meteor.npmRequire("excel4node");
    var wbOpts = {
      // allowInterrupt: true,
    };
    var wb = new xlsx.WorkBook(wbOpts);
    var wsOpts = {
      view: {
        zoom: 100,
      },
      fitToPage: {
        fitToHeight: 100,
        orientation: "landscape",
      },
    };

    var singleInquiry = req.query && req.query.id;
    var query = {};
    if (singleInquiry) {
      query._id = req.query.id;
    }
    var inquiries = Inquiries.find(query, {
      sort: {
        createdAt: -1,
      },
    }).fetch();

    var generalOnly = false;
    var proposalOnly = false;
    var cabshieldOnly = false;
    if (singleInquiry) {
      var singleDocument = inquiries[0];
      generalOnly =
        singleDocument && singleDocument.subject === "generalInquiry";
      cabshieldOnly =
        singleDocument && singleDocument.subject === "cabshieldInquiry";
      proposalOnly =
        singleDocument && singleDocument.subject === "proposalRequest";
    }
    if (!singleInquiry || generalOnly) {
      var generalInquiryWs = wb.WorkSheet("General Inquiries", wsOpts);
      generalInquiryWs.Cell(1, 1).String("Created");
      generalInquiryWs.Cell(1, 2).String("Name");
      generalInquiryWs.Cell(1, 3).String("Company");
      generalInquiryWs.Cell(1, 4).String("Phone");
      generalInquiryWs.Cell(1, 5).String("Email");
      generalInquiryWs.Cell(1, 6).String("Address");
      generalInquiryWs.Cell(1, 7).String("City");
      generalInquiryWs.Cell(1, 8).String("State");
      generalInquiryWs.Cell(1, 9).String("Zip");
      generalInquiryWs.Cell(1, 10).String("Referred By");
      generalInquiryWs.Cell(1, 11).String("Comments");

      var j = 2;
      inquiries.forEach(function (inquiry) {
        if (inquiry && inquiry.subject === "generalInquiry") {
          generalInquiryWs.Cell(j, 1).Date(inquiry.created);
          generalInquiryWs.Cell(j, 2).String(inquiry.contactName);
          generalInquiryWs.Cell(j, 3).String(inquiry.contactCompany);
          generalInquiryWs.Cell(j, 4).String(inquiry.contactPhone);
          generalInquiryWs.Cell(j, 5).String(inquiry.contactEmail);
          generalInquiryWs.Cell(j, 6).String(inquiry.contactAddress);
          generalInquiryWs.Cell(j, 7).String(inquiry.contactCity);
          generalInquiryWs.Cell(j, 8).String(inquiry.contactState);
          generalInquiryWs.Cell(j, 9).String(inquiry.contactZip);
          generalInquiryWs.Cell(j, 10).String(inquiry.howHear);
          generalInquiryWs.Cell(j, 11).String(inquiry.formComments);
          j++;
        }
      });
    }

    if (!singleInquiry || cabshieldOnly) {
      var generalInquiryWs = wb.WorkSheet("CabShield Inquiries", wsOpts);
      generalInquiryWs.Cell(1, 1).String("Created");
      generalInquiryWs.Cell(1, 2).String("Name");
      generalInquiryWs.Cell(1, 3).String("Company");
      generalInquiryWs.Cell(1, 4).String("Phone");
      generalInquiryWs.Cell(1, 5).String("Email");
      generalInquiryWs.Cell(1, 6).String("Address");
      generalInquiryWs.Cell(1, 7).String("City");
      generalInquiryWs.Cell(1, 8).String("State");
      generalInquiryWs.Cell(1, 9).String("Zip");
      generalInquiryWs.Cell(1, 10).String("Referred By");
      generalInquiryWs.Cell(1, 11).String("Details");

      var j = 2;
      inquiries.forEach(function (inquiry) {
        if (inquiry && inquiry.subject === "cabshieldInquiry") {
          generalInquiryWs.Cell(j, 1).Date(inquiry.created);
          generalInquiryWs.Cell(j, 2).String(inquiry.contactName || "");
          generalInquiryWs.Cell(j, 3).String(inquiry.contactCompany || "");
          generalInquiryWs.Cell(j, 4).String(inquiry.contactPhone || "");
          generalInquiryWs.Cell(j, 5).String(inquiry.contactEmail || "");
          generalInquiryWs.Cell(j, 6).String(inquiry.contactAddress || "");
          generalInquiryWs.Cell(j, 7).String(inquiry.contactCity || "");
          generalInquiryWs.Cell(j, 8).String(inquiry.contactState || "");
          generalInquiryWs.Cell(j, 9).String(inquiry.contactZip || "");
          generalInquiryWs.Cell(j, 10).String(inquiry.howHear || "");
          generalInquiryWs.Cell(j, 11).String(inquiry.formComments || "");
          j++;
        }
      });
    }

    if (!singleInquiry || proposalOnly) {
      var generalInquiryWs = wb.WorkSheet("Proposal Requests", wsOpts);
      generalInquiryWs.Cell(1, 1).String("Created");
      generalInquiryWs.Cell(1, 2).String("Company");
      generalInquiryWs.Cell(1, 3).String("Representative");
      generalInquiryWs.Cell(1, 4).String("Contact (Other)");
      generalInquiryWs.Cell(1, 5).String("Address");
      generalInquiryWs.Cell(1, 6).String("City");
      generalInquiryWs.Cell(1, 7).String("State");
      generalInquiryWs.Cell(1, 8).String("Zip");
      generalInquiryWs.Cell(1, 9).String("Email");
      generalInquiryWs.Cell(1, 10).String("Phone");

      generalInquiryWs.Cell(1, 11).String("Project Name");
      generalInquiryWs.Cell(1, 12).String("Project Date");
      generalInquiryWs.Cell(1, 13).String("Project Type");
      generalInquiryWs.Cell(1, 14).String("Dimensions");
      generalInquiryWs.Cell(1, 15).String("Cab Size");
      generalInquiryWs.Cell(1, 16).String("Linear Feet");
      generalInquiryWs.Cell(1, 17).String("Shell");
      generalInquiryWs.Cell(1, 18).String("Car Top");
      generalInquiryWs.Cell(1, 19).String("Wall Panels");
      generalInquiryWs.Cell(1, 20).String("Front Returns");
      generalInquiryWs.Cell(1, 21).String("Door Style");
      generalInquiryWs.Cell(1, 22).String("Door Size");
      generalInquiryWs.Cell(1, 23).String("Ceiling & Frame");
      generalInquiryWs.Cell(1, 24).String("Fan");
      generalInquiryWs.Cell(1, 25).String("Sill");
      generalInquiryWs.Cell(1, 26).String("Handrails");

      generalInquiryWs.Cell(1, 27).String("Referred By");
      generalInquiryWs.Cell(1, 28).String("Comments");

      var j = 2;
      inquiries.forEach(function (inquiry) {
        if (inquiry && inquiry.subject === "proposalRequest") {
          generalInquiryWs.Cell(j, 1).Date(inquiry.created);
          generalInquiryWs.Cell(j, 2).String(inquiry.contactCompany);
          generalInquiryWs.Cell(j, 3).String(inquiry.contactRepresentative);
          generalInquiryWs.Cell(j, 4).String(inquiry.contactContactOther);
          generalInquiryWs.Cell(j, 5).String(inquiry.contactAddress);
          generalInquiryWs.Cell(j, 6).String(inquiry.contactCity);
          generalInquiryWs.Cell(j, 7).String(inquiry.contactState);
          generalInquiryWs.Cell(j, 8).String(inquiry.contactZip);
          generalInquiryWs.Cell(j, 9).String(inquiry.contactEmail);
          generalInquiryWs.Cell(j, 10).String(inquiry.contactPhone);

          generalInquiryWs.Cell(j, 11).String(inquiry.cabProjectName);
          generalInquiryWs.Cell(j, 12).String(inquiry.cabProjectDate);
          generalInquiryWs.Cell(j, 13).String(inquiry.cabProjectType);
          generalInquiryWs.Cell(j, 14).String(inquiry.cabDimension);
          generalInquiryWs.Cell(j, 15).String(inquiry.cabSize);
          generalInquiryWs.Cell(j, 16).String(inquiry.cabLinearFeet);
          generalInquiryWs.Cell(j, 17).String(inquiry.cabShell);
          generalInquiryWs.Cell(j, 18).String(inquiry.cabTop);
          generalInquiryWs.Cell(j, 19).String(inquiry.cabWallPanels);
          generalInquiryWs.Cell(j, 20).String(inquiry.cabFrontReturns);
          generalInquiryWs.Cell(j, 21).String(inquiry.cabDoorStyle);
          generalInquiryWs.Cell(j, 22).String(inquiry.cabDoorSize);
          generalInquiryWs.Cell(j, 23).String(inquiry.cabCeilingFrame);
          generalInquiryWs.Cell(j, 24).String(inquiry.cabFan);
          generalInquiryWs.Cell(j, 25).String(inquiry.cabSill);
          generalInquiryWs.Cell(j, 26).String(inquiry.cabHandrails);

          generalInquiryWs.Cell(j, 27).String(inquiry.howHear);
          generalInquiryWs.Cell(j, 28).String(inquiry.formComments);
          j++;
        }
      });
    }

    wb.write("Inquiry Data.xlsx", res);
  } else if (req.url.startsWith("/user-audit-data")) {
    var token = req.query && req.query.token;
    var user = token
      ? Meteor.users.findOne({
          "services.resume.loginTokens.hashedToken":
            Accounts._hashLoginToken(token),
        })
      : undefined;
    if (typeof user === "undefined" || !isAdmin(user)) {
      next();
      return;
    }
    var xlsx = Meteor.npmRequire("excel4node");
    var wbOpts = {
      // allowInterrupt: true,
    };
    var wb = new xlsx.WorkBook(wbOpts);
    var wsOpts = {
      view: {
        zoom: 100,
      },
      fitToPage: {
        fitToHeight: 100,
        orientation: "landscape",
      },
    };

    var ws = wb.WorkSheet("User Audit", wsOpts);

    var dateStyle = wb.Style();
    dateStyle.Number.Format("mm/dd/yyyy hh:mm:ss");

    ws.Cell(1, 1).String("Date/Time");
    ws.Cell(1, 2).String("Name");
    ws.Cell(1, 3).String("Email");
    ws.Cell(1, 4).String("Role");
    ws.Cell(1, 5).String("Action");
    var auditRecords = UserAudit.find(
      {},
      {
        sort: {
          createdAt: -1,
        },
      }
    ).fetch();
    var j = 2;
    auditRecords.forEach(function (auditRecord) {
      if (auditRecord) {
        var user = Meteor.users.findOne(auditRecord.userId);
        if (user) {
          ws.Cell(j, 1).Date(auditRecord.createdAt).Style(dateStyle);
          ws.Cell(j, 2).String(user.profile.name);
          ws.Cell(j, 3).String(user.emails[0].address);
          ws.Cell(j, 4).String(auditRecord.role);
          ws.Cell(j, 5).String(auditRecord.action);
          j++;
        }
      }
    });

    wb.write("Employee Audit Data.xlsx", res);
  } else {
    // Other urls will have default behaviors
    next();
  }
});

}).call(this);
