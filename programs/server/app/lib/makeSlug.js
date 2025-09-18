(function(){makeSlug = function makeSlug(slugcontent, noLower) {
  // convert to lowercase (important: since on next step
  //special chars are defined in lowercase only)
  if (!noLower) {
    slugcontent = slugcontent.toLowerCase();
  }
  // convert special chars
  var accents = {
    a: /\u00e1/g,
    e: /\u00e9/g,
    i: /\u00ed/g,
    o: /\u00f3/g,
    u: /\u00fa/g,
    n: /\u00f1/g
  };
  for (var i = 0; i < accents.length; i++) {
    slugcontent = slugcontent.replace(accents[i], i);
  }

  var slugcontentHyphens = slugcontent.replace(/\s/g, '-');
  var finishedslug = slugcontentHyphens.replace(/[^a-zA-Z0-9\-]/g, '');
  if (!noLower) {
    finishedslug = finishedslug.toLowerCase();
  }
  return finishedslug;
};

}).call(this);
