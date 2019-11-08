#!groovy

// Pull Request builds might fail due to missing diffs: https://issues.jenkins-ci.org/browse/JENKINS-45997
// Pull Request builds relationship to their targets branch: https://issues.jenkins-ci.org/browse/JENKINS-37491

@NonCPS
def cancelPreviousBuilds() {
    def jobName = env.JOB_NAME
    def buildNumber = env.BUILD_NUMBER.toInteger()
    /* Get job name */
    def currentJob = Jenkins.instance.getItemByFullName(jobName)

    /* Iterating over the builds for specific job */
    for (def build : currentJob.builds) {
        /* If there is a build that is currently running and it's not current build */
        if (build.isBuilding() && build.number.toInteger() != buildNumber) {
            /* Than stopping it */
            build.doStop()
        }
    }
}

pipeline {
    agent any

    parameters { booleanParam(name: 'FORCE_VALGRIND', defaultValue: false, description: 'Execute Valgrind even for a PR branch') }

    environment {
	OBS_TARGET_PROJECT = 'VR:Dartmouth'
	OBS_TARGET_REPO = 'standard'
	OBS_TARGET_ARCH = 'x86_64'
	// # Replace : with _ in project name, as osc-buildpkg does
	OSC_BUILD_ROOT = "${WORKSPACE}" + '/build-root/' + "${env.OBS_TARGET_PROJECT.replace(':','_')}" + '-' + "${env.OBS_TARGET_REPO}" + '-' + "${OBS_TARGET_ARCH}"
	DH_VERBOSE = 1
	DH_QUIET = 0
	DEB_BUILD_OPTIONS ='verbose'
    }

    options {
	timeout(time: 180, unit: 'MINUTES') // Hopefully maximum even when Valgrind is included!
	checkoutToSubdirectory("vyatta-dataplane")
	quietPeriod(90) // Wait 90 seconds in case there are more SCM pushes/PR merges coming
    }

    stages {

	// A work around, until this feature is implemented: https://issues.jenkins-ci.org/browse/JENKINS-47503
	stage('Cancel older builds') { steps { script {
	    cancelPreviousBuilds()
        }}}

	stage('OSC config') {
	    steps {
		sh 'printenv'
		// Build scripts with tasks to perform in the chroot
		sh """
cat <<EOF > osc-buildpackage_buildscript_default
export BUILD_ID=\"${BUILD_ID}\"
export JENKINS_NODE_COOKIE=\"${JENKINS_NODE_COOKIE}\"
dpkg-buildpackage -jauto -us -uc -b
EOF
"""
		sh """
cat <<EOF > osc-buildpackage_buildscript_scan_build
export BUILD_ID=\"${BUILD_ID}\"
export JENKINS_NODE_COOKIE=\"${JENKINS_NODE_COOKIE}\"
scan-build --status-bugs --use-cc clang --use-c++ clang++ -o clangScanBuildReports -maxloop 64 dpkg-buildpackage -jauto -us -uc -b
EOF
"""
	    }
	}

	// Workspace specific chroot location used instead of /var/tmp
	// Allows parallel builds between jobs, but not between stages in a single job
	// TODO: Enhance osc-buildpkg to support parallel builds from the same pkg_srcdir
	// TODO: probably by allowing it to accept a .conf file from a location other than pkg_srcdir

	stage('OSC Build') {
	    steps {
		dir('vyatta-dataplane') {
		    sh """
cat <<EOF > .osc-buildpackage.conf
OSC_BUILDPACKAGE_TMP=\"${WORKSPACE}\"
OSC_BUILDPACKAGE_BUILDSCRIPT=\"${WORKSPACE}/osc-buildpackage_buildscript_default\"
EOF
"""
		    sh "osc-buildpkg -v -g -T -P ${env.OBS_TARGET_PROJECT} ${env.OBS_TARGET_REPO} -- --trust-all-projects --build-uid='caller'"
		}
	    }
	}

	stage('clang Static Analysis') {
	    environment {
		CC = 'clang'
		CXX ='clang++'
		DEB_BUILD_OPTIONS = 'nocheck'
	    }
	    steps {
		dir('vyatta-dataplane') {
		    sh """
cat <<EOF > .osc-buildpackage.conf
OSC_BUILDPACKAGE_TMP=\"${WORKSPACE}\"
OSC_BUILDPACKAGE_BUILDSCRIPT=\"${WORKSPACE}/osc-buildpackage_buildscript_scan_build\"
EOF
"""
		    sh "osc-buildpkg -v -g -T -P ${env.OBS_TARGET_PROJECT} ${env.OBS_TARGET_REPO} -- --trust-all-projects --build-uid='caller' --extra-pkgs='clang' --extra-pkgs='llvm-dev'"
		}
	    }
	    post {
		failure {
		    echo 'clang analyzer found issues'
		    dir('clangScanBuildReports'){
			sh "cp ${env.OSC_BUILD_ROOT}/usr/src/packages/BUILD/clangScanBuildReports/*/* ."
		    }
		    publishHTML target: [
			allowMissing: false,
			alwaysLinkToLastBuild: false,
			keepAll: false,
			reportDir: 'clangScanBuildReports',
			reportFiles: 'index.html',
			reportTitles: 'clang scan-build Static Analysis',
			reportName: 'clang scan-build Static Analysis Report'
		    ]
		}
	    }
	}

	stage('Valgrind') {
	    when { anyOf {
                expression { env.CHANGE_ID == null } // If this is not a Pull Request
                expression { return params.FORCE_VALGRIND } // Or if forced
	    }}
	    environment {
		DEB_BUILD_PROFILES = 'pkg.vyatta-dataplane.valgrind'
	    }
	    steps {
		dir('vyatta-dataplane') {
		    sh """
cat <<EOF > .osc-buildpackage.conf
OSC_BUILDPACKAGE_TMP=\"${WORKSPACE}\"
OSC_BUILDPACKAGE_BUILDSCRIPT=\"${WORKSPACE}/osc-buildpackage_buildscript_default\"
EOF
"""
		    sh "osc-buildpkg -v -g -T -P ${env.OBS_TARGET_PROJECT} ${env.OBS_TARGET_REPO} -- --trust-all-projects --build-uid='caller' --extra-pkgs='valgrind'"
		}
	    }
	}

	stage('cppcheck Static Analysis') {
	    when {expression { env.CHANGE_ID == null }} // Not when this is a Pull Request
	    environment {
		extra_cppcheck_parameters = '--xml-version=2 --error-exitcode=0'
	    }
	    steps {
		dir('vyatta-dataplane') {
		    sh "./scripts/cppcheck_wrapper.sh 2> ${WORKSPACE}/cppcheck.xml"
		}
		// TODO: Currently this doesn't cause a failure
		// TODO: Fail if the number of cppcheck errors is above some threshold.
		// TODO: Better yet would for there to be none and then remove
		//       --error-exitcode=0 above so that it fails on any reported error.
		sh 'cppcheck-htmlreport --title="Vyatta Dataplane" --file=cppcheck.xml --report-dir=cppcheck_reports --source-dir=vyatta-dataplane'
	    }
	    post {
		success {
		    publishHTML target: [
			allowMissing: false,
			alwaysLinkToLastBuild: false,
			keepAll: false,
			reportDir: 'cppcheck_reports',
			reportFiles: 'index.html',
			reportTitles: 'cppcheck Static Analysis',
			reportName: 'cppcheck Static Analysis Report'
		    ]
		}
	    }
	}

	stage('Code Stats') {
	    when {expression { env.CHANGE_ID == null }} // Not when this is a Pull Request
	    steps {
		sh 'sloccount --duplicates --wide --details vyatta-dataplane > sloccount.sc'
		sloccountPublish pattern: '**/sloccount.sc'
	    }
	}

	stage('checkpatch') {
	    when {
		allOf {
		    // Only if this is a Pull Request
		    expression { env.CHANGE_ID != null }
		    expression { env.CHANGE_TARGET != null }
		}
	    }
	    steps {
		dir('vyatta-dataplane') {
		//TODO: Path to checkpatch.pl should not be hardcoded!
		    sh "PATH=~/linux-vyatta/scripts:$PATH ./scripts/checkpatch_wrapper.sh upstream/${env.CHANGE_TARGET} origin/${env.BRANCH_NAME}"
		}
	    }
	}

    } // stages

    post {
        always {
	    sh 'rm -f *.deb'
	    sh "osc chroot --wipe --force --root ${env.OSC_BUILD_ROOT}"
	    deleteDir()
        }
        success {
            echo 'Winning'
        }
        failure {
            echo 'Argh... something went wrong'
	    emailext (
		subject: "FAILED: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]'",
		body: """<p>FAILED: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]':</p>
			 <p>Check console output at "<a href="${env.BUILD_URL}">${env.JOB_NAME} [${env.BUILD_NUMBER}]</a>"</p>""",
		recipientProviders: [culprits()]
	    )
        }
    }
}
