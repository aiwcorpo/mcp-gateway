// The tests start containers, so the full run needs the Docker socket, and a socket is root on the agent. It is given to the
// branch main only, on an agent labelled 'docker-trusted' that runs nothing from change requests. A change request gets a job
// without the socket and without credentials that only compiles; the full run follows after the merge.
// No credentials are bound: the mcp-contracts artifacts come from Maven Central.
// BRANCH_NAME exists in multibranch jobs only; a plain pipeline job has GIT_BRANCH ("origin/main"). A change request has CHANGE_ID.
def onMain() {
    String branch = env.BRANCH_NAME ?: (env.GIT_BRANCH ?: '').replaceFirst('^origin/', '')
    return branch == 'main' && !env.CHANGE_ID
}

pipeline {
    agent none
    stages {
        stage('change request') {
            when { expression { !onMain() } }
            agent { docker { image 'maven:3.9.12-eclipse-temurin-25' } }
            steps {
                sh './mvnw -B -DskipTests verify'
            }
        }
        stage('verify') {
            when { expression { onMain() } }
            agent {
                docker {
                    label 'docker-trusted'
                    image 'maven:3.9.12-eclipse-temurin-25'
                    args '-v /var/run/docker.sock:/var/run/docker.sock'
                }
            }
            steps {
                sh './mvnw -B verify'
            }
            post {
                always {
                    junit allowEmptyResults: false, testResults: 'target/surefire-reports/TEST-*.xml'
                }
            }
        }
    }
}
