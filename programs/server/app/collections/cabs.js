(function(){Cabs = new Meteor.Collection('cabs');

Cabs.allow({
  insert: function () {
    return false;
  },
  update: function () {
    return false;
  },
  remove: function () {
    return false;
  }
});

}).call(this);
