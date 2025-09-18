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
