(function(){
  var subs = new SubsManager({
    cacheLimit: 9999,
    expireIn: 9999
  });
Router.configure({
  layoutTemplate: 'homeLayout',
  notFoundTemplate: 'notFound',
  loadingTemplate: 'loading',
  onAfterAction: function () {
    if (this.data && this.data() && this.data().page) {
      document.title = this.data().page.metaTitle;
      $('meta[name="title"]').remove();
      $('head').append('<meta name="title" content="' +
        this.data().page.metaTitle + '">\n');
      $('meta[name="description"]').remove();
      $('head').append('<meta name="description" content="' +
        this.data().page.metaDescription + '">\n');
      $('meta[name="subject"]').remove();
      $('head').append('<meta name="subject" content="' +
        this.data().page.metaSubject + '">\n');
      $('meta[name="keywords"]').remove();
      $('head').append('<meta name="keywords" content="' +
        this.data().page.metaKeywords + '">\n');
    }
  },
  onBeforeAction: function () {
    if (Meteor.isClient) {
      Session.set('editing', null);
      Session.set('errorMessage', null);
      Session.set('infoMessage', null);
      Session.set('isVisible', null);
      Session.set('employeeFormVisible', null);
      Session.set('showDesigner', null);
    }

    if (_.include(['signIn', 'signUp'], this.route.getName())) {
      if (Meteor.user() && Meteor.user().profile) {
        if (Meteor.user().profile.customer) {
          Router.go('/customer-portal');
        }
      }
    }

    if (_.include(['dashboard', 'customerPortal'], this.route.getName())) {
      if (isCustomer(Meteor.user())) {
        Router.go('customerPortal');
      } else {
        Router.go('/');
      }
    }

    this.next();
  },
  onStop: function () {
    if (Meteor.isClient) {
      s();
    }
  }
});
  var defaultSessions = {
    'mainOption': null,
    'panelOption': null,
    'panelAMaterialOption': null,
    'panelBMaterialOption': null,
    'panelCMaterialOption': null,
    'panelDMaterialOption': null,
    'panelEMaterialOption': null,
    'panelAMaterial': null,
    'panelBMaterial': null,
    'panelCMaterial': null,
    'panelDMaterial': null,
    'panelEMaterial': null,
    'revealsOption': null,
    'revealsMaterial': null,
    'activeHandrailsOption': null,
    'handrailsOption': null,
    'handrailsMaterial': null,
    'activeCeilingOption': null,
    'ceilingOption': null,
    'ceilingMaterial': null,
    'ceilingPanelOption': null,
    'ceilingAMaterial': null,
    'ceilingBMaterial': null,
    'finalize': null,
    'savedCab': null,
    'editing': null,
    'savingCab': null
  };
  var setSessions = function () {
    for (var prop in defaultSessions) {
      Session.set(prop, defaultSessions[prop]);
    }
  };
  AccountController = RouteController.extend({
    resetPassword: function () {
      // NOTE: prompt below is very crude, but demonstrates the solution
      Accounts.resetPassword(
        this.params.token,
        prompt('enter new password'),
        function (error) {
          Router.go('/');
        });
    },
    verifyEmail: function () {
      Accounts.verifyEmail(
        this.params.token,
        function () {
          Router.go('/');
        });
    }
  });
  Router.map(function () {
    this.route('/', {
      template: 'page',
      data: function () {
        return {
          page: Pages.findOne({
            slug: 'design-studio'
          })
        };
      },
      waitOn: function () {
        return [
          subs.subscribe('settings'),
          subs.subscribe('pages'),
          subs.subscribe('heros')
        ];
      },
      fastRender: true
    });
    this.route('/customer-portal', {
      name: 'customerPortal',
      waitOn: function () {
        return [
          subs.subscribe('settings'),
          subs.subscribe('pages'),
          subs.subscribe('customerCabs'),
          subs.subscribe('users'),
          subs.subscribe('documents')
        ];
      },
      fastRender: true
    });
    this.route('/tools-resources/design-studio/designer/launch/:cabType', {
      name: 'launchCab',
      onBeforeAction: function () {
        if (!this.params.cabType) {
          Router.go('/tools-resources/design-studio/designer');
        }
        if (!((Meteor.isClient) ? Meteor.userId() : this.userId)) {
          Router.go('/signIn');
        } else {
          this.next();
        }
      },
      data: function () {
        return {
          cabType: this.params.cabType
        };
      },
      waitOn: function () {
        return [
          subs.subscribe('settings'),
          subs.subscribe('pages'),
        ];
      }
    });
    this.route('/tools-resources/design-studio/designer', {
      name: 'designCab',
      waitOn: function () {
        return [subs.subscribe('settings'),
          subs.subscribe('pages'),
        ];
      },
      onBeforeAction: function () {
        if (!((Meteor.isClient) ? Meteor.userId() : this.userId)) {
          Router.go('/signIn');
        } else {
          this.next();
        }
      }
    });
    this.route('/uploads/cabpdfs/:file', {
      action: function () {
        var fs = Npm.require('fs');
        var filePath = process.env.PWD + '/.uploads/cabpdfs/' + this.params
          .file;
        var data = fs.readFileSync(filePath, data);
        this.response.writeHead(200, {
          'Content-Type': 'document/pdf'
        });
        this.response.write(data);
        this.response.end();
      },
      where: ['server']
    });
    this.route('/cab/:cabID', {
      template: 'printCab',
      layoutTemplate: 'cabLayout',
      subscriptions: function () {
        subs.subscribe('cab', this.params.cabID);
      },
      onBeforeAction: function () {
        Session.set('cabID', this.params.cabID);
        this.next();
      },
      onStop: function () {
        Session.set('cabID', null);
        Session.set('mainOption', null);
      }
    });
    this.route('/cabOnly/:cabID', {
      template: 'cabOnly',
      layoutTemplate: 'bareLayout',
      subscriptions: function () {
        subs.subscribe('cab', this.params.cabID);
      },
      onBeforeAction: function () {
        Session.set('cabID', this.params.cabID);
        this.next();
      },
      onStop: function () {
        Session.set('cabID', null);
        Session.set('mainOption', null);
      }
    });
    this.route('/signIn', {});
    this.route('/signUp', {});
    this.route('/forgotPassword', {});
    this.route('/signOut', {
      onBeforeAction: function () {
        Meteor.logout(function () {
          return Router.go('/');
        });
        this.next();
      }
    });
    this.route('/reset-password/:token', {
      controller: 'AccountController',
      action: 'resetPassword'
    });
    this.route('/verify-email/:token', {
      controller: 'AccountController',
      action: 'verifyEmail'
    });
    this.route('/enroll-account/:token', {
      controller: 'AccountController',
      action: 'resetPassword'
    });

    this.route('notFound', {
      path: '*'
    });
  });
}).call(this);
