runBuild {
    stage ('prep') {
        sh('dotnet --version')
        sh('rm -rf ./artifacts')
        sh('dotnet clean')
    }

    stage ('NuGet auth') {
        sh('dotnet nuget add source http://nexus:8081/repository/nuget-hosted --store-password-in-clear-text --username $NEXUS_AUTOMATION_USERNAME --password $NEXUS_AUTOMATION_PASSWORD')
    }

    stage ('test') {
        sh('dotnet test')
        sh('rm -rf ./artifacts')
        sh('dotnet clean')
    }

   stage('build') {
        sh('dotnet build -c Release Digirati.JWT.sln')
   }

   stage('publish') {
       if(publish()) {
            sh('dotnet nuget push --source http://nexus:8081/repository/nuget-hosted --skip-duplicate -k $NEXUS_NUGET_API_KEY "./artifacts/*.nupkg"')
       }
   }
}

void runBuild(Closure pipeline) {
    node('linux') {
        container('buildkit') {
            checkout(scm)

            pipeline()
        }
    }
}

boolean publish() {
  return env.BRANCH_NAME == 'master' || env.TAG_NAME
}