require 'spec'
require 'spec/rake/spectask'

task :default => [:spec]

desc "Run all examples"
Spec::Rake::SpecTask.new('spec') do |t|
  if File.exists?('spec/spec.opts')
    t.spec_opts << '--options' << 'spec/spec.opts'
  end
  t.spec_files = FileList['spec/*.rb']
end

namespace :db do

  desc "Run SimpleDB/dev local server"
  task :start do
    sh('python spec/mock-simpledb/simpledb_dev.py')
  end

  desc "Clear the local mock server data"
  task :clear do
    rm_rf('spec/mock-simpledb/data')
    rm_rf('test.log')
  end

end
