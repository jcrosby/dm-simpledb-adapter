require 'rubygems'
require 'dm-core'
require 'dm-validations'
require 'right_aws'
require 'uuid'

module DataMapper
  module Adapters

    # A SimpleDB adapter for DataMapper built on the Rightscale gem.
    class SimpleDbAdapter < AbstractAdapter

      attr_reader :db

      def initialize(name, uri_or_options)
        super
        @domain = @uri[:domain] ||= 'dm-simpledb'
        @db = RightAws::SdbInterface.new(
          @uri[:access_key], @uri[:secret_key], @uri.reject { |k,v| k == :access_key || k == :secret_key })
      end

      def create(resources)
        resources.each do |resource|
          resource.id = "#{Time.now.utc.to_i}:#{UUID.generate}"
          @db.put_attributes(@domain, item_name(resource), resource.attributes)
        end.size
      end

      def read_one(query)
      end

      def read_many(query)
      end

      def update(attributes, query)
      end

      def delete(query)
      end

      protected

      def item_name(resource)
        "#{resource.model}.#{resource.id}"
      end

      module Migration
        def storage_exists?(storage_name)
        end

        def create_model_storage(repository, model)
          @db.create_domain(@domain)
        end

        def destroy_model_storage(repository, model)
          @db.list_domains[:domains].each do |domain|
            @db.delete_domain(domain)
          end # TODO consider only deleting matching type.* keys
        end
      end

      include Migration
    end

    SimpledbAdapter = SimpleDbAdapter
  end
end
