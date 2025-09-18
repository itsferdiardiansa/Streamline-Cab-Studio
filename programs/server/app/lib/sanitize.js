(function(){sanitize = function sanitize(fileName) {
  return fileName
    .replace(/\//g, '')
    .replace(/\.\.+/g, '.').replace(/ /g, "_");
};

}).call(this);
