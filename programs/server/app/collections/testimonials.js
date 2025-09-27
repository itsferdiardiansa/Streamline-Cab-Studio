(function(){Testimonials = new Meteor.Collection('testimonials');

Testimonials.allow({
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
