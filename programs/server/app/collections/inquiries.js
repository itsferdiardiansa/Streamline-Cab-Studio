(function(){Inquiries = new Meteor.Collection('inquiries');

Inquiries.allow({
  insert: function (userId) {
    // anyone can fill out the contact form
    return true;
  },
  update: function (userId) {
    return isAdminById(userId);
  },
  remove: function (userId) {
    return isAdminById(userId);
  }
});

}).call(this);
