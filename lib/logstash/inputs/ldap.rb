# encoding: utf-8
require "logstash/inputs/base"
require "logstash/namespace"
require "stud/interval"
require "socket" # for Socket.gethostname

class LdapConnectTimeout < Timeout::Error;end

class LogStash::Inputs::Ldap < LogStash::Inputs::Base
  config_name "ldap"

  default :codec, "plain"

  config :bind_dn,        :validate => :string, :required => true
  config :bind_password,  :validate => :string, :required => true
  config :ldap_uri,       :validate => :string, :required => true
  config :cacert_path,    :validate => :string, :required => false
	config :filter,         :validate => :string, :default => "(objectclass=*)"
  config :interval,       :validate => :number
  config :timeout,        :validate => :number, :default => 10
  config :timestamp_filter_on,            :validate => :boolean,  :default => false
  config :timestamp_filter_field,         :validate => :string,   :default => "reqstart"
  config :timestamp_filter_field_end,     :validate => :string,   :default => nil
  config :timestamp_filter_save_metadata, :validate => :boolean,  :default => true
  config :timestamp_filter_metadata_path, :validate => :string,
                                          :default => "#{ENV['HOME']}/.logstash_ldap_last_run"

  public
  def format_ldap_time(time)
    time.utc.strftime("%Y%m%d%H%M%SZ")
  end

  def register
    require 'net-ldap'
    require 'uri'
    require "stud/interval"
    require "yaml"
    # timeout has problems in jruby 1.7.19, using jruby_timeout instead
    # require 'timeout'

    begin
      parsed_uri = URI.parse @ldap_uri
      raise ArgumentError.new("uri is not an ldap uri") unless
              [ URI::LDAP, URI::LDAPS ].index parsed_uri.class
      @host   = parsed_uri.host
      @port   = parsed_uri.port
      @ssl    = parsed_uri.scheme == "ldaps" ? true : false
      @base   = parsed_uri.dn
      @scope  = case parsed_uri.scope
        when "sub"
          Net::LDAP::SearchScope_WholeSubtree
        when "base"
          Net::LDAP::SearchScope_BaseObject
        when "single"
          Net::LDAP::SearchScope_SingleLevel
      end
    rescue ArgumentError, URI::InvalidURIError => e
      @logger.error("Not an LDAP/LDAPS uri", :error_message => e.message)
      raise e
    end

    begin
      @parsed_filter=Net::LDAP::Filter.from_rfc2254 @filter
    rescue ArgumentError, URI::InvalidURIError => e
      @logger.error("Invalid filter #{@filter}", :error_message => e.message)
      raise e
    end

    if @cacert_path and not File.readable? @cacert_path
      @logger.error "Unreadable #{@cacert_path}"
      raise IOError.new("Unreadable #{@cacert_path}")
    end

    # load timestamp_filter_last_value from file if exists
    if @timestamp_filter_on && File.exist?(@timestamp_filter_metadata_path)
      @timestamp_filter_last_value = YAML.load( File.read( @timestamp_filter_metadata_path ) )
      @logger.debug("read timestamp_filter_last_value: #{@timestamp_filter_last_value}")
    elsif @timestamp_filter_on
      @timestamp_filter_last_value = "00000101000000.000000Z"
      @logger.debug("set timestamp_filter_last_value as default: #{@timestamp_filter_last_value}")
    end
  end

  def entry_to_event( entry )
    data = {}
    entry.attribute_names.each do |an|
      data[an.to_s] = entry[an]
    end
    #data["ldap_server"] = @host
    event = LogStash::Event.new( data )
    decorate( event )
    event
  end

  def connect()
    ldap=nil
    begin
      tls_options = (not @cacert_path) ? {} : {
        :ca_file => @cacert_path
      }
      enc = ( not @ssl ) ? nil : {
          :method => :simple_tls,
          :tls_options => tls_options
      }
      jruby_timeout(@timeout, LdapConnectTimeout) do
        ldap=Net::LDAP.new(
          :host => @host, :base => @base, :port => @port, :encryption => enc,
          :auth => {
            :username => @bind_dn, :password => @bind_password, :method => :simple
          }
          #,:connect_timeout => @timeout
        )
      end
    rescue LdapConnectTimeout => ex
      @logger.error("Timeout connecting to LDAP")
      raise ex
    rescue Net::LDAP::Error => ex
      @logger.error("Failed to connect to LDAP", :error_message => ex.message)
      raise ex
    else
      return ldap
    end
  end

  # alternate timeout for jruby
  # https://gist.github.com/jorgenpt/1356797
  def jruby_timeout(sec,klass)
    return yield(sec) if sec == nil or sec.zero?
    thread = Thread.new { yield(sec) }

    if thread.join(sec).nil?
      java_thread = JRuby.reference(thread)
      thread.kill
      java_thread.native_thread.interrupt
      thread.join(0.15)
      raise klass, 'execution expired'
    else
      thread.value
    end
  end

  def run_once(queue)
    begin
      filter= if not @timestamp_filter_on
        @parsed_filter
      else
        @parsed_filter.&(
          Net::LDAP::Filter.ge( timestamp_filter_field, @timestamp_filter_last_value )
        )
      end
      @logger.debug("Using filter: #{filter.to_s}")

      timestamp_filter_last_value = @timestamp_filter_last_value

      # jruby_timeout overcoming old jruby problems
      jruby_timeout(@timeout, LdapConnectTimeout ) do
        ris = @ldap.search( :base => @base,
                            :filter => filter,
                            :return_result => false,
                            # maybe, someday 
                            #:time_limit => @timeout,
                            :scope => Net::LDAP::SearchScope_SingleLevel) do |entry|
          yield(entry)
          if @timestamp_filter_on
            entry_timestamp = if @timestamp_filter_field_end
              entry[@timestamp_filter_field_end][0].to_s
            else
              entry[@timestamp_filter_field][0].to_s
            end

            timestamp_filter_last_value = entry_timestamp if
                  entry_timestamp > timestamp_filter_last_value
          end
        end
      end
    rescue LdapConnectTimeout => e
      @logger.error("Timeout running query")
    rescue Net::Ldap::Error => e
      @logger.error("LDAP error running query: #{e.message}")
    rescue Exception => e
      @logger.error("Error running query [#{e.class}]: #{e}", :error_message => e.message)
      raise e
    else
      @timestamp_filter_last_value = timestamp_filter_last_value
      update_state_file if @timestamp_filter_save_metadata
    end
  end
  def run(queue)
    @ldap=connect()
    loop do
      run_once(queue) do |entry|
        event = entry_to_event entry
        queue << event
      end
      # run only once if @interval not set
      break if (not @interval) or stop?
      Stud.stoppable_sleep(@interval) { stop? }
    end
  end

  def stop
    # nothing to do in this case so it is not necessary to define stop
    # examples of common "stop" tasks:
    #  * close sockets (unblocking blocking reads/accepts)
    #  * cleanup temporary files
    #  * terminate spawned threads
  end
  def update_state_file
    if @timestamp_filter_save_metadata
      @logger.debug("saving timestamp_filter_last_value: #{@timestamp_filter_last_value}")
      File.write(@timestamp_filter_metadata_path, YAML.dump(@timestamp_filter_last_value))
    end
  end
end
