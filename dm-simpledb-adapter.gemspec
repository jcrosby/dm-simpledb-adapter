Gem::Specification.new do |s|
  s.specification_version = 2 if s.respond_to? :specification_version=
  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.name              = "dm-simpledb-adapter"
  s.version           = "0.1.0"
  s.date              = "2009-02-16"
  s.summary           = "A write-through caching SimpleDB adapter for DataMapper"
  s.description       = "A write-through caching SimpleDB adapter for DataMapper"
  s.authors           = ["Jon Crosby"]
  s.email             = "jon@joncrosby.me"
  s.homepage          = "http://github.com/jcrosby/dm-simpledb-adapter"
  s.files             = %w[
    dm-simpledb-adapter.gemspec
    README
    Rakefile
    lib/simpledb_adapter.rb
    spec/mock-simpledb/portalocker.py
    spec/mock-simpledb/simpledb_dev.py
    spec/mock-simpledb/templates/CreateDomain.xml
    spec/mock-simpledb/templates/DeleteAttributes.xml
    spec/mock-simpledb/templates/DeleteDomain.xml
    spec/mock-simpledb/templates/GetAttributes.xml
    spec/mock-simpledb/templates/ListDomains.xml
    spec/mock-simpledb/templates/PutAttributes.xml
    spec/mock-simpledb/templates/Query.xml
    spec/mock-simpledb/templates/QueryWithAttributes.xml
    spec/mock-simpledb/templates/error.xml
    spec/simpledb_adapter_spec.rb
    spec/spec.opts
    spec/spec_helper.rb
  ]
  s.test_files        = s.files.select { |path| path =~ /^spec\/.*_spec.rb/ }
  s.rubyforge_project = "dm-simpledb"
  s.rubygems_version  = "1.1.1"
  s.add_dependency 'uuid', '= 2.0.1'
  s.add_dependency 'dm-core', '= 0.9.10'
  s.add_dependency 'dm-validations', '= 0.9.10'
  s.add_dependency 'right_aws', '~> 1.9.0'
end
