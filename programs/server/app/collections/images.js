(function(){var docPath = '';
if (Meteor.isServer) {
  docPath = process.env.PWD + '/.uploads/';
}
var imageStore = new FS.Store.FileSystem("originals", {
  path: docPath + 'images/',
  beforeWrite: function (fileObj) {
      return {
        name: sanitize(fileObj.original.name)
      };
    }
    /*,
    transformWrite: function(fileObj, readStream, writeStream) {
        readStream.pipe(writeStream);
    }*/
});
var thumbStore = new FS.Store.FileSystem("thumbs", {
  path: docPath + 'thumbs/',
  transformWrite: function (fileObj, readStream, writeStream) {
    gm(readStream, fileObj.name).resize(null, '200').stream().pipe(
      writeStream);
  },
  beforeWrite: function (fileObj) {
    return {
      name: sanitize(fileObj.original.name)
    };
  }
});

Images = new FS.Collection("images", {
  stores: [
    imageStore, thumbStore
  ],
  filter: {
    //maxSize: 1048576, //in bytes
    allow: {
      contentTypes: ['image/*'],
      extensions: [
        'jpg', 'jpeg', 'png', 'gif'
      ]
    },
    onInvalid: function (message) {
      console.log(message);
    }
  }
});

Images.allow({
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
