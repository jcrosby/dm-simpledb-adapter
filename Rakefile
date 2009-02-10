require 'spec'
require 'spec/rake/spectask'

task :default => [:spec]

desc "Run SimpleDB/dev local server"
task :start_local_sdb do
  sh('python spec/mock-simpledb/simpledb_dev.py')
end

desc "Run all examples"
Spec::Rake::SpecTask.new('spec') do |t|
  if File.exists?('spec/spec.opts')
    t.spec_opts << '--options' << 'spec/spec.opts'
  end
  t.spec_files = FileList['spec/*.rb']
end
