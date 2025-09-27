(function(){News = new Meteor.Collection('news');

News.allow({
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

Meteor.methods({

});

}).call(this);
