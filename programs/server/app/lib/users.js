(function(){convertToCSV = function (objArray) {
  var array = typeof objArray !== 'object' ? JSON.parse(objArray) : objArray;
  var str = '';

  var line = 'Created,';
  line += 'Email,';
  line += 'Company,';
  line += 'Name,';
  line += 'Phone,';
  line += 'UserName';

  line.slice(0, line.Length - 1);

  str += line + '\r\n';

  for (var i = 0; i < array.length; i++) {
    line = '';
    line += array[i].createdAt + ',';
    line += array[i].emails[0].address + ',';
    line += array[i].profile.company + ',';
    line += array[i].profile.name + ',';
    line += array[i].profile.phone + ',';
    line += array[i].username;

    line.slice(0, line.Length - 1);

    str += line + '\r\n';
  }
  window.open("data:text/csv;charset=utf-8," + escape(str));
};
isAdminById = function (userId) {
  var user = Meteor.users.findOne(userId);
  return !!(user && isAdmin(user));
};
isAdmin = function (user) {
  user = (typeof user === 'undefined') ? Meteor.user() : user;
  return !!user && !!user.profile && !!user.profile.admin;
};
/*
adminUsers = function() {
    return Meteor.users.find({
        profile.admin: true
    }).fetch();
}*/
isStaffById = function (userId) {
  var user = Meteor.users.findOne(userId);
  return !!(user && isStaff(user));
};
isStaff = function (user) {
  user = (typeof user === 'undefined') ? Meteor.user() : user;
  return !!user && !!user.profile && !!user.profile.staff;
};
/*
staffUsers = function() {
    return Meteor.users.find({
        isStaff: true
    }).fetch();
}*/
isCustomerById = function (userId) {
  var user = Meteor.users.findOne(userId);
  return !!(user && isCustomer(user));
};
isCustomer = function (user) {
  user = (typeof user === 'undefined') ? Meteor.user() : user;
  return !!user && !!user.profile && !!user.profile.customer;
};
/*
customerUsers = function() {
    return Meteor.users.find({
        isCustomer: true
    }).fetch();
}*/
getUserName = function (user) {
  return user.username;
};
/*
getDisplayName = function(user) {
    return (user && user.profile && user.profile.firstname &&
    user.profile.lastname) ? user.profile.firstname + ' ' +
    user.profile.lastname : user.username;
};
getDisplayNameById = function(userId) {
    return getDisplayName(Meteor.users.findOne(userId));
};*/
getEmail = function (user) {
  if (user && user.emails && user.emails[0]) {
    return user.emails[0].address;
  } else {
    return '';
  }
};
getEmailById = function (userId) {
  var user = Meteor.users.findOne({
    '_id': userId
  });
  return getEmail(user);
};
getCurrentUserEmail = function () {
  return Meteor.user() ? getEmail(Meteor.user()) : '';
};

getProfileImage = function (user) {
  if (user.profile && user.profile.image) {
    return user.profile.image;
  }
  return null;
};
userProfileComplete = function (user) {
  return !!getEmail(user);
};
findLast = function (user, collection) {
  return collection.findOne({
    userId: user._id
  }, {
    sort: {
      createdAt: -1
    }
  });
};
timeSinceLast = function (user, collection) {
  var now = new Date().getTime();
  var last = findLast(user, collection);
  if (!last) {
    return 999;
    // if this is the user's first post or comment ever, stop here
  }
  return Math.abs(Math.floor((now - last.createdAt) / 1000));
};
getUserSetting = function (setting, defaultValue, user) {
  var user = (typeof user == 'undefined') ? Meteor.user() : user;
  var defaultValue = (typeof defaultValue == "undefined") ? null :
    defaultValue;
  var settingValue = getProperty(user.profile, setting);
  return (settingValue == null) ? defaultValue : settingValue;
};
getProperty = function (object, property) {
  // recursive function to get nested properties
  var array = property.split('.');
  if (array.length > 1) {
    var parent = array.shift();
    // if our property is not at this level, call function again
    //one level deeper if we can go deeper, else return null
    return (typeof object[parent] == "undefined") ? null : getProperty(object[
      parent], array.join('.'))
  } else {
    // else return property
    return object[array[0]];
  }
};
getLoginToken = function() {
  return localStorage.getItem('Meteor.loginToken');
};

}).call(this);
