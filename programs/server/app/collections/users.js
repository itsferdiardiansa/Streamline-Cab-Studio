(function(){Meteor.users.allow({
  insert: function (userId, doc) {
    if (!userId) {
      return false;
    }
    return isAdminById(userId);
  },
  update: function (userId, doc) {
    if (!userId) {
      return false;
    }
    return isAdminById(userId) || doc._id === userId;
  },
  remove: function (userId, doc) {
    if (!userId) {
      return false;
    }
    return isAdmin(Meteor.user());
  }
});

}).call(this);
