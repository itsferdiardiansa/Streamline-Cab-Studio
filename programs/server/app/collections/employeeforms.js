(function(){EmployeeForms = new Meteor.Collection('employeeforms');

EmployeeForms.allow({
  insert: function (userId, doc) {
    return isAdminById(userId);
  },
  update: function (userId, doc) {
    return true;
  },
  remove: function (userId, doc) {
    return isAdminById(userId);
  }
});

}).call(this);
