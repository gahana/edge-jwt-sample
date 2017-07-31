'use strict';

module.exports = function(grunt) {
    grunt.initConfig({
        cucumberjs: {
            features: [
                // 'features/jws.feature'
                // 'features/jwe.feature'
                // 'features/jws-jwe.feature'
            ],
            options: {
                // tags: '@current',
                format: 'pretty'
            }
        }
    });

    grunt.loadNpmTasks('grunt-cucumber');
    grunt.registerTask('default', ['cucumberjs']);
}