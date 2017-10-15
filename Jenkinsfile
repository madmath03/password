pipeline {
    agent any
    tools {
        maven 'Maven 3.3'
        jdk 'JDK 1.8'
    }
    stages {
        stage ('Initialize') {
            steps {
                sh '''
                    java -version
                    mvn --version
                '''
            }
        }

        stage ('Build') {
            steps {
                sh 'mvn clean compile' 
            }
        }

        stage ('Test') {
            steps {
                sh 'mvn test verify' 
            }
        }

        stage ('Packaging') {
            steps {
                sh 'mvn package' 
            }
        }

        stage ('Reporting') {
            steps {
                sh 'mvn site' 
            }
        }
    }
}