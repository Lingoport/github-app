require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl'     # Verifies the webhook signature
require 'jwt'         # Authenticates a GitHub App
require 'time'        # Gets ISO 8601 representation of a Time object
require 'logger'      # Logs debug statements
require 'http'
require "base64"
require 'open3'

set :port, 3000
set :bind, '0.0.0.0'


class GHAapp < Sinatra::Application

  # Expects that the private key in PEM format. Converts the newlines
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  CLIENT_ID = ENV['GITHUB_CLIENT_ID']

  CLIENT_SECRET = ENV['GITHUB_CLIENT_SECRET']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end

  get '/' do
  #  if request.query_string != nil then
  #    logger.debug request.query_string[5..24]
     response=HTTP
                .post('https://github.com/login/oauth/access_token/?client_id='+CLIENT_ID+'&client_secret='+CLIENT_SECRET+'&code='+request.query_string[5..24])
     logger.debug response.to_s
     @accesstoken = response.to_s[13..52]
     logger.debug @accesstoken
     get_user=HTTP.headers(:accept => "application/vnd.github.machine-man-preview+json")
                  .auth("Bearer #@accesstoken")
                  .get('https://api.github.com/user')
     logger.debug get_user.to_s              
#    end
     "Hello World"
  end

  # Before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature
    authenticate_app
    # Authenticate the app installation in order to run API operations
    authenticate_installation(@payload)
  end


  post '/event_handler' do

    case request.env['HTTP_X_GITHUB_EVENT']
    when 'push'
      handle_push_event(@payload)
    when 'pull_request'
      if @payload['action'] === 'opened'
         handle_push_event(@payload)
      end
    end
    200 # success status
  end


  helpers do
    def handle_push_event(payload)
      err_FILE = '/tmp/err.txt'
      #COMMENT_WORKSPACE=
    #  `java -jar /home/centos/globalyzer-lite/globalyzer-lite.jar "/home/centos/lite.xml" -pp "$COMMENT_WORKSPACE"  --report-path "/home/centos/GlobalyzerScans" 2> #{ERR_FILE}`
      githubURL = payload['repository']['commits_url'].gsub(/repos./, 'repos.'=>'')
      githubURL = githubURL.gsub(/commits\{\/sha\}/, '/commits{/sha}'=>'')
      githubLogin = payload['sender']['login']
      githubOauth = @installation_token
      repo = payload['repository']['full_name']
      commitBranch = payload['ref'].gsub(/refs\/heads\//, 'refs/heads/'=>'')
      commitSha = payload['after']
      githubPath = payload['repository']['url']
      reportsDir = '/home/centos/tmp/'+commitSha
      githubURL = 'https://api.github.com'
    #  logger.debug githubOauth
      logger.debug githubURL
      logger.debug githubLogin
      logger.debug repo
      logger.debug commitBranch
      logger.debug githubPath
      logger.debug reportsDir
    #  `java -jar /home/centos/lingoport-github-pull-request-cli.jar --add-comment-commit -gu "$githubURL" -gl "$githubLogin" -gt "$githubOauth" -gr "$repo" -br "$commitBranch" -gcs "$commitSha" -gp "$githubPath" -rd "$reportsDir" 2> ${ERR_FILE}`
      reportsDir = '/home/centos/GlobalyzerScans'

      `rm /home/centos/payload.json`
      File.open("/home/centos/payload.json","a+") do |f|
      f.puts payload
      end
    #  `/home/centos/gitapp.sh`
    #  cmd = '/home/centos/gitapp.sh'
      cmd = 'java -jar /home/centos/lingoport-github-pull-request-cli.jar --add-comment-commit -gu '+githubURL+ ' -gl '+githubLogin+' -gt '+githubOauth+' -gr '+repo+' -br '+commitBranch + ' -gcs '+commitSha+ ' -gp '+githubPath +' -rd '+reportsDir
      logger.debug cmd
      Open3.popen3(cmd) do |stdin, stdout, stderr, wait_thr|
        while line = stdout.gets
          puts line
        end
      end
    end

    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail  "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app an not altererd by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minute maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')
      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.                 .headers(:accept => "application/vnd.github.machine-man-preview+json")

    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      #logger.debug "Bearer #@installation_token"
      response=HTTP.auth("Bearer #@installation_token")
                   .get('https://api.github.com/repos/LiliJi/CET-CitySmart/contents/CitySmart/src/InfoForm.js').to_s
      response_json = JSON.parse response
      filecontent = response_json['content']

      #logger.debug Base64.decode64(filecontent)
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature` looks something
    # like this: "sha1=123456".
    # See https://developer.github.com/webhooks/securing/ for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

  end

  run! if __FILE__ == $0
end
