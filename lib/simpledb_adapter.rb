require 'rubygems'
gem 'dm-core', '= 0.9.10'
require 'dm-core'
gem 'dm-validations', '= 0.9.10'
require 'dm-validations'
require 'right_aws'
require 'uuid'

module DataMapper
  module Adapters

    # A SimpleDB adapter for DataMapper built on the RightScale gem.
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
          # TODO consider compound key support
          first_key = keys_for_resource(resource)[0] #rescue (raise "At least one key required")
          unless resource.instance_variable_get(first_key)
            resource.instance_variable_set(first_key, "#{Time.now.utc.to_i}:#{UUID.generate}")
          end
          @db.put_attributes(@domain, item_name_for_resource(resource), resource.attributes)
        end.size
      end

      def read_one(query)
        item = items_for_query(query)[0]
        unless item == nil || item.empty?
          query.model.load(data_for_item_name(item, query), query)
        end
      end

      def read_many(query)
        items = items_for_query(query)
        Collection.new(query) do |set|
          items.each do |item|
            set.load(data_for_item_name(item, query))
          end
        end
      end

      def update(attributes, query)
        attributes = attributes.to_a.map { |a| [a[0].name, a[1]] }.to_hash
        item_name = "#{query.model}.#{query.conditions[0][2]}"
        @db.put_attributes(@domain, item_name, attributes, true) ? 1 : 0
      end

      def delete(query)
        item = items_for_query(query)[0]
        @db.delete_attributes(@domain, item) ? 1 : 0
      end

      protected

      def data_for_item_name(item, query)
        attributes = @db.get_attributes(@domain, item)[:attributes]
        query.fields.map { |f| attributes[f.field.to_s] }
      end

      def items_for_query(query)
        sdb_query = query.conditions.map do |condition|
          "[#{@db.escape(condition[1].name)} #{operator_for(condition[0])} #{@db.escape(condition[2])}]"
        end.join(' intersection ') # TODO implement all set operations
        @db.query(@domain, sdb_query)[:items]
      end

      def operator_for(dm_symbol)
        # TODO implement all comparators
        case dm_symbol
        when :eql; '='
        end
      end

      def item_name_for_resource(resource)
        "#{resource.model}." + keys_for_resource(resource).map do |key|
          resource.instance_variable_get(key)
        end.join(':')
      end

      def keys_for_resource(resource)
        resource.class.key(self.name).map do |property|
          property.instance_variable_name
        end
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
