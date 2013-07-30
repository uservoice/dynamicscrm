# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "dynamicscrm/version"

Gem::Specification.new do |s|
  s.name        = "dynamicscrm"
  s.version     = DynamicsCRM::VERSION
  s.authors     = ["Raimo Tuisku"]
  s.email       = ["dev@uservoice.com"]
  s.homepage    = "http://developer.uservoice.com"
  s.summary     = %q{Client library for DynamicsCRM API}
  s.description = %q{The gem provides Ruby-bindings to DynamicsCRM API}

  s.rubyforge_project = "dynamicscrm"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  s.add_development_dependency "rspec", '>= 1.0.5'
  s.add_runtime_dependency 'httparty'
  s.add_runtime_dependency 'uuid'
  s.add_runtime_dependency 'awesome_print'
  s.add_runtime_dependency 'nokogiri'
end
