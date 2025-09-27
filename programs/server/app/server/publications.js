(function(){"use strict";
Meteor.publish('pages', function () {
  try {
    return Pages.find({}, {
      fields: {
        _id: true,
        title: true,
        sidebar: true,
        slug: true,
        portal: true,
        hero: true,
        parent: true,
        weight: true,
        text: true,
        text2: true,
        calloutText1: true,
        calloutText2: true,
        image: true,
        active: true,
        metaDescription: true,
        metaTitle: true,
        metaSubject: true,
        metaKeywords: true,
        updated: true,
        isCustomerPortal: true,
        isProjectPhotoGallery: true,
        isDesignStudio: true,
        isFeaturedGallery: true,
        isNewsPage: true,
        isCompanyPortal: true
      }
    });
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('heros', function () {
  try {
    return Images.find({
      'metadata.page': {
        $exists: true
      }
    });
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('contentImages', function () {
  try {
    return Images.find({
      'metadata.pageContent': {
        $exists: true
      }
    });
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('customerCabs', function () {
  Counts.publish(this, 'cabs', Cabs.find(), { noReady: true });
  if (isCustomerById(this.userId)) {
    return Cabs.find({
      owner: this.userId
    });
  }
  return this.ready();
});

Meteor.publish('cabs', function (page, limit, filter) {
  filter = filter || {};
  check(page, Number);
  check(limit, Number);
  check(filter, Object)
  Counts.publish(this, 'cabs', Cabs.find(filter), { noReady: true });
  return Cabs.find(filter, {
    sort: {
      saved: -1
    },
    skip: page * limit,
    limit: limit,
  });
});

Meteor.publish('cab', function (cabID) {
  check(cabID, String);
  try {
    return Cabs.find({
      _id: cabID
    });
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('settings', function () {
  try {
    return Settings.find({});
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('images', function () {
  try {
    return Images.find({
      'metadata.page': {
        $exists: false
      },
      'metadata.pageContent': {
        $exists: false
      }
    });
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('documents', function () {
  try {
    return Documents.find({});
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('employeeforms', function () {
  try {
    if (isAdminById(this.userId)) {
      return EmployeeForms.find({});
    } else {
      var email = getEmailById(this.userId);
      email = email ? email : "";
      return EmployeeForms.find(
        { $or: [{"availableFor": null},
                {"availableFor": ""},
                {"availableFor": email.toLowerCase().trim()}]});
    }
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('currentNewsItem', function (slug) {
  check(slug, String);
  try {
    return News.find({
      slug: slug
    }, {
      fields: {
        _id: true,
        title: true,
        content: true,
        slug: true,
        image: true,
        created: true,
        posted: true,
        active: true,
        updated: true
      }
    });
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('news', function () {
  try {
    return News.find({}, {
      fields: {
        _id: true,
        title: true,
        content: true,
        slug: true,
        image: true,
        created: true,
        posted: true,
        active: true,
        updated: true
      }
    });
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('testimonials', function () {
  try {
    return Testimonials.find({}, {
      fields: {
        _id: true,
        title: true,
        content: true,
        weight: true,
        created: true,
        active: true,
        updated: true,
        image: true
      }
    });
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('inquiries', function () {
  try {
    Counts.publish(this, 'inquiries', Inquiries.find({ "subject": "generalInquiry" }), { noReady: true });
    Counts.publish(this, 'proposals', Inquiries.find({ "subject": "proposalRequest" }), { noReady: true });
    if (isAdminById(this.userId)) {
      return Inquiries.find({}, {
        fields: {
          _id: true,
          contactEmail: true,
          contactName: true,
          contactCompany: true,
          contactState: true,
          contactRepresentative: true,
          contactZip: true,
          contactContactOther: true,
          contactAddress: true,
          contactPhone: true,
          contactCity: true,
          cabProjectName: true,
          cabWallPanels: true,
          cabProjectDate: true,
          cabFrontReturns: true,
          cabProjectType: true,
          cabDoorStyle: true,
          cabDimension: true,
          cabDoorSize: true,
          cabSize: true,
          cabCeilingFrame: true,
          cabLinearFeet: true,
          cabFan: true,
          cabShell: true,
          cabSill: true,
          cabTop: true,
          cabHandrails: true,
          howHear: true,
          formComments: true,
          subject: true,
          created: true
        }
      });
    } else {
      return this.ready();
    }
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('galleries', function () {
  try {
    return Galleries.find({}, {
      fields: {
        _id: true,
        title: true,
        description: true,
        weight: true,
        created: true,
        active: true,
        updated: true,
        path: true,
        images: true
      }
    });
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('careers', function () {
  try {
    return Careers.find({}, {
      fields: {
        _id: true,
        position: true,
        description: true,
        contactEmail: true,
        active: true,
        region: true,
        posted: true,
        doc: true,
        created: true,
        updated: true
      }
    });
  } catch (error) {
    console.log(error);
  }
});

Meteor.publish('users', function () {
  try {
    Counts.publish(this, 'customers', Meteor.users.find({'profile.customer': true}), { noReady: true });
    Counts.publish(this, 'staff', Meteor.users.find({'profile.staff': true}), { noReady: true });

    var fields = {
      '_id': true,
      'username': true,
      'profile': true,
      'emails': true,
      'createdAt': true,
      'updated': true,
      'vcard': true
    };

    if (isAdminById(this.userId)) {
      return Meteor.users.find({}, {
        fields: fields
      });
    }
    if (isStaffById(this.userId)) {
      return Meteor.users.find({
        $or: [{
          'profile.staff': true
        }, {
          'profile.customer': true
        }]
      }, {
        fields: fields
      });
    }
    return Meteor.users.find({
      $or: [{
        'profile.staff': true,
        'profile.active': true
      }, {
        _id: this.userId
      }]
    }, {
      fields: fields
    });
  } catch (error) {
    console.log(error);
  }
});

}).call(this);
