(function(){var DateFormats = {
  year: 'YYYY',
  tiny: 'MMM YYYY',
  short: 'DD MMMM - YYYY',
  normalTime: 'MMMM DD, YYYY HH:mm',
  table: 'MMM Do YYYY',
  normal: 'MMMM DD, YYYY',
  medium: 'dddd DD.MM.YYYY HH:mm',
  long: 'dddd DD.MM.YYYY HH:mm',
  forFile: 'MM-DD-YYYY-HH-mm-X'
};
/* jshint -W020 */
formatEklundsDate = function (datetime, format) {
  var m = moment(datetime);
  if (DateFormats.hasOwnProperty(format)) {
    return m.format(DateFormats[format]);
  }
  return m.fromNow();
};

convertDateInput = function (dateString) {
  var date = '';
  if (dateString) {
      try {
          date = new Date(dateString + 'T00:00:00').toLocaleDateString('en-US');
      } catch (error) {
          console.error('invalid date: ' + dateString);            
      }
  }
  return date;
}
}).call(this);
