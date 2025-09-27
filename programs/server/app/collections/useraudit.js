(function(){UserAudit = new Meteor.Collection('useraudit');

UserAudit.allow({
  insert: function (userId, doc) {
    if (!userId) {
      return false;
    }
    return doc.userId === userId;
  },
  update: function (userId, doc) {
    return false;
  },
  remove: function (userId, doc) {
    if (!userId) {
      return false;
    }
    return isAdmin(Meteor.user());
  }
});

}).call(this);
