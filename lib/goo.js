'use strict';

try {
  module.exports = require('./native/goo');
} catch (e) {
  module.exports = require('./js/goo');
}
