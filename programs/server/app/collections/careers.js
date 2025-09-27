(function(){Careers = new Meteor.Collection('careers');

Careers.allow({
  insert: function (userId) {
    return isAdminById(userId);
  },
  update: function (userId) {
    return isAdminById(userId);
  },
  remove: function (userId) {
    return isAdminById(userId);
  }
});

}).call(this);
