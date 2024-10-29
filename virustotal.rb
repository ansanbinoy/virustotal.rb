#!/bin/ruby

require 'optparse'
require 'net/http'
require 'json'

class VirusTotal
    @@apiKeys = nil
    @@api = nil
    @@domains = nil
    @@subs = nil

    def initialize(api, apiKeys, domains, subs)
        @@api = api
        @@apiKeys = apiKeys
        @@domains = domains
        @@subs = subs
    end 

    def get_subdomains(domain)
        subdomains = Array[]
        begin
            api = URI("#{@@api}?apikey=#{@@apiKeys[0]}&domain=#{domain}")
            subdomains.append(domain)
            data = ::Net::HTTP.get_response(api)
            if Integer(data.code) == 204 || Integer(data.code) == 403
                sleep 30
                @@apiKeys.map do |apik|
                    api = URI("#{@@api}?apikey=#{apik}&domain=#{domain}")
                    data = ::Net::HTTP.get_response(api)
                    if Integer(data.code) == 200
                        subdomains.concat(JSON::parse(data.body())["subdomains"])
                        break
                    end
                end 
            else
                subdomains.concat(JSON::parse(data.body())["subdomains"])
            end
        rescue => error
            puts error.message
        end 
        subdomains
    end 

    def get_urls(subdomains)
        def get_resp(api, dom)
            data = ::Net::HTTP.get_response(api)
            if Integer(data.code) == 204 || Integer(data.code) == 403
                sleep 30
                @@apiKeys.map do |apik|
                    api = URI("#{@@api}?apikey=#{apik}&domain=#{dom}")
                    data = ::Net::HTTP.get_response(api)
                    if Integer(data.code) == 200
                        return data
                    end
                end 
            else
                return data
            end
        end 
        urls = Array[]
        apikeys = @@apiKeys.dup
        subdomains.sort.map do |dom|
            if apikeys.length() >= 1
                begin
                    api = URI("#{@@api}?apikey=#{apikeys.pop()}&domain=#{dom}")
                    data = get_resp(api, dom)
                    data = JSON::parse(data.body)
                    data["undetected_urls"].map do |url|
                        puts url[0]
                        urls.append(url[0])
                    end
                rescue => err
                    # puts err.message
                    nil
                end 
            else
                begin
                    apikeys = @@apiKeys.dup
                    sleep 30
                    api = URI("#{@@api}?apikey=#{apikeys.pop()}&domain=#{dom}")
                    data = get_resp(api, dom)
                    data = JSON::parse(data.body)
                    data["undetected_urls"].map do |url|
                        urls.append(url[0])
                    end
                rescue => err
                    # puts err.message
                    nil
                end 
            end 
        end 
        # puts urls
        urls
    end

    def run
        if @@subs
            @@domains.sort.map do |domain|
                begin
                    get_urls(get_subdomains(domain))
                rescue => err
                    nil
                end
            end
        else 
            begin
                get_urls(@@domains)
            rescue => err
                nil
            end 
        end
    end 
end 
        
def get_stdin
    input = Array[]
    STDIN.readlines.map do |line|
        next if line.strip.empty?
        input.append(line.strip)
    end
    input
end

def main
    api = "https://www.virustotal.com/vtapi/v2/domain/report"
    domain = nil  # domains = [""]
    apiKeys = nil # apiKeys = ["Key1", "Key2"]

    args = Hash[]
    args[:subs] = false
    if not apiKeys.nil?
        args[:path] = true
    end
    if STDIN.stat.pipe?
        args[:file] = true
        domains = get_stdin()
    end

    optprs = OptionParser::new do |parser|
        parser.banner= "Usage: ./virustotal.rb [options]"
        parser.on("-f FILE", "--file FILE", "File that contain domains.", required=true) { |o| args[:file] = o }
        parser.on("-s", "--[no-]subs", "Take subdomains from given domains.") { |o| args[:subs] = o }
        parser.on("-p PATH", "--path PATH", "File path that contain apiKeys. [if not declared in source]", required=true){ |o| args[:path] = o}
    end
    optprs.parse!

    if args[:file].nil? || args[:path].nil?
        puts optprs.help
        exit 1
    end

    if apiKeys.nil?
        apiKeys = File.readlines(args[:path]).map do |ln|
            ln.strip
        end
    end

    if domains.nil?
        domains = File.readlines(args[:file]).map do |ln|
            ln.strip
        end 
    end

    VirusTotal::new(api, apiKeys, domains, args[:subs]).run
end 


if caller.length == 0
    main
end
