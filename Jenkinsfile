// Thin wrapper: all logic is in ci/run.sh.
//
// The tests start containers, so the full run needs the Docker socket, and a socket is root on the agent. It is given to the
// branch main only, on an agent labelled 'docker-trusted' that runs nothing from change requests. A change request gets a job
// without the socket and without credentials: hygiene checks and the self-test of ci/run.sh (the full run follows after the merge).
// Credentials for the mcp-contracts artifacts (MCP_MAVEN_REPOSITORY_URL, _USER, _PASSWORD) are Jenkins credentials bound in the
// main job only.
pipeline {
    agent none
    stages {
        stage('change request') {
            when { not { branch 'main' } }
            agent { docker { image 'maven:3.9.12-eclipse-temurin-25' } }
            steps {
                sh 'ci/self-test.sh'
                sh 'ci/run.sh hygiene'
            }
        }
        stage('verify') {
            when { branch 'main' }
            agent {
                docker {
                    label 'docker-trusted'
                    image 'maven:3.9.12-eclipse-temurin-25'
                    args '-v /var/run/docker.sock:/var/run/docker.sock'
                }
            }
            steps {
                withCredentials([string(credentialsId: 'mcp-maven-repository-url', variable: 'MCP_MAVEN_REPOSITORY_URL'),
                                 usernamePassword(credentialsId: 'mcp-maven-repository', usernameVariable: 'MCP_MAVEN_REPOSITORY_USER',
                                                  passwordVariable: 'MCP_MAVEN_REPOSITORY_PASSWORD')]) {
                    sh 'ci/self-test.sh'
                    sh 'ci/run.sh verify'
                }
            }
            post {
                always {
                    junit allowEmptyResults: false, testResults: '*/target/surefire-reports/TEST-*.xml'
                }
            }
        }
    }
}
