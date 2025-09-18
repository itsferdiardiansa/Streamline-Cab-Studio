(function(){(function () {
  "use strict";
  Meteor.startup(function () {
    var settings = Settings.findOne();
    if (settings && !settings.cabTypes) {
      settings.cabTypes = [{
        type: 'passenger',
        name: 'Passenger',
        cabs: [{
          cab: 'velocity',
          name: 'Velocity',
          description: 'With three horizontal panels on each wall and vertical accent panels in both rear corners, this modern and classy cab interior is one of Eklund’s most popular configurations.'
        }, {
          cab: 'stellar',
          name: 'Stellar',
          description: 'Similar to our Origin cab design, Stellar is simple and classic but with thinner reveals (space between the panels) and a defined handrail backer. The clean lines and classic design go well with almost any type of property and architecture. '
        }, {
          cab: 'inertia',
          name: 'Inertia',
          description: 'Asymmetrical and modern, Inertia’s stylish accent panels and juxtaposed handrails make this design a work of art that stands out from more traditional cab designs.'
        }, {
          cab: 'aurora',
          name: 'Aurora',
          description: 'Featuring traditional rear wall panels, Aurora is set off by full-length ceiling to floor side wall panels. The clean design includes a rear-wall handrail only. The Aurora ceiling compliments this design with a center downlight panel. '
        }, {
          cab: 'aurora-glow',
          name: 'Aurora Glow',
          description: 'Popular in current architectural designs, the Aurora Glow accent backlighting offers beauty and high efficiency. Following this new design trend, the backlit center panel extends up into a backlit center ceiling panel. Special backlit-designated materials are offered in the cab design studio.'
        }, {
          cab: 'origin',
          name: 'Origin',
          description: 'Origin is Eklund’s original ‘standard cab’ offering that has been a customer favorite for more than 10 years. This timeless cab design features a simple, symmetrical panel design within a fixed stainless steel frame structure.'
        }]
      }, {
        type: 'observation',
        name: 'Observation',
        disabled: true,
        cabs: [{
          cab: 'coming-up',
          name: 'Coming Up',
          description: ''
        }]
      }, {
        type: 'freight-service',
        name: 'Freight/Service',
        disabled: true,
        cabs: [{
          cab: 'portal',
          name: 'Portal',
          description: ''
        }]
      }];
      Settings.update(settings._id, settings);
    }
    //console.log(settings);
    // disable expiration token. Defaults to 90 days.
    Accounts.config({
      //loginExpirationInDays: 90
      /*, restrictCreationByEmailDomain: 'eklunds.com'*/
    });
  });
}());

}).call(this);
