(function(){var docPath = '';
if (Meteor.isServer) {
  docPath = process.env.PWD + '/.uploads/';
}

var docStore = new FS.Store.FileSystem("documents", {
  path: docPath + 'documents/',
  beforeWrite: function (fileObj) {
    return {
      name: sanitize(fileObj.original.name)
    };
  }
});

Documents = new FS.Collection("documents", {
  stores: [docStore],
  filter: {
    maxSize: 10485760, //in bytes = 10MB
    allow: {
      //contentTypes: ['application/vnd.openxmlformats*','application/msword',
      //'text/x-vcard', 'text/directory'],
      extensions: ['pdf', 'doc', 'docx', 'vcf']
    },
    onInvalid: function (message) {
      console.log(message);
      alert(message);
    }
  }
});

Documents.allow({
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
