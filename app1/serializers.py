from rest_framework import serializers
from .models import Category, Test, Cart, User, EmailOTP, CustomerSuggestion, SampleCollectionAddress, SampleRequisition
from django.contrib.auth.hashers import make_password
import json  # <-- add


# Create a serializer for the Category model
class CategorySerializer(serializers.ModelSerializer):
    # This will include a list of subcategories in the serialized category data
    subcategories = serializers.StringRelatedField(many=True)

    class Meta:
        model = Category
        fields = ['id', 'category_name', 'image_url', 'description', 'info', 'subcategories', 'created_at', 'updated_at']


class TestSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = Test
        fields = '__all__'        

class CartSerializer(serializers.ModelSerializer):
    test_name = serializers.CharField(source="test.test_name", read_only=True)  # Assuming 'test' has a 'name' field
    test_price = serializers.DecimalField(source="test.test_price", max_digits=10, decimal_places=2, read_only=True)  # Assuming 'test' has a 'price' field
    image_url = serializers.CharField(source="test.image_url", read_only=True)

    class Meta:
        model = Cart
        fields = ['id', 'test_name', 'test_price', 'quantity', 'image_url']    


class OrderSummarySerializer(serializers.ModelSerializer):
    test_name = serializers.CharField(source="test.test_name", read_only=True)  # Assuming 'test' has a 'name' field
    test_price = serializers.DecimalField(source="test.test_price", max_digits=10, decimal_places=2, read_only=True)  # Assuming 'test' has a 'price' field
    image_url = serializers.CharField(source="test.image_url", read_only=True)

    class Meta:
        model = Cart
        fields = ['id', 'test_name', 'test_price', 'quantity', 'image_url']  

class RegisterSerializer(serializers.ModelSerializer):
    # Accept password as input, but store it as password_hash
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ['full_name', 'email', 'password', 'phone', 'address', 'user_role']
        extra_kwargs = {
            'email': {'required': True},
            'phone': {'required': False},
            'address': {'required': False},
            'user_role': {'required': False},
            'password' : {'write_only': True},
        }

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already in use")
        return value

    def validate_phone(self, value):
        if value and (not str(value).isdigit() or len(str(value)) > 10):
            raise serializers.ValidationError("Phone number must be numeric and at most 10 digits.")
        return value

    def create(self, validated_data):
        # Pop plain password and hash it
        password = validated_data.pop('password')
        validated_data['password'] = make_password(password)

        return User.objects.create(**validated_data)


class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not value:
            raise serializers.ValidationError("Email is required")
        return value


class VerifyOTPSerializer(serializers.Serializer):
    userData = serializers.DictField(child=serializers.CharField(), required=True)
    otp = serializers.CharField()

    def validate(self, data):
        user_data = data.get("userData", {})
        required_fields = ["email", "full_name", "password"]

        for field in required_fields:
            if field not in user_data or not user_data[field]:
                raise serializers.ValidationError(f"{field.replace('_', ' ').capitalize()} is required")

        return data


class SuggestionSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerSuggestion
        fields = ['selected_options', 'message']

class SampleCollectionAddressSerializer(serializers.ModelSerializer):
    # expose id so frontend can store it and pass as pickup_address
    class Meta:
        model = SampleCollectionAddress
        fields = [
            'id',  # <-- added
            'location',
            'building_or_room',
            'department',
            'street_address',
            'city',
            'state_province',
            'region',
            'postal_code',
            'preferred_time_slot',
            'preferred_date',
            'contact_person',
            'contact_phone',
            'alternate_phone',
            'is_business_address',
            'pickup_instructions',
            'access_notes',
        ]
        read_only_fields = ('id',)

# Accept JSON either as a real JSON value or a JSON-encoded string (multipart safe)
class JSONStringOrListField(serializers.JSONField):
    def to_internal_value(self, data):
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                raise serializers.ValidationError("Must be valid JSON (stringified array/object).")
        return super().to_internal_value(data)

class SampleRequisitionSerializer(serializers.ModelSerializer):
    # Allow passing pickup_address by id; validate ownership in create()
    pickup_address = serializers.PrimaryKeyRelatedField(
        queryset=SampleCollectionAddress.objects.all(),
        required=False,
        allow_null=True,
    )

    # Coerce arrays sent via multipart FormData
    storage_conditions = JSONStringOrListField(required=False)
    hazard_info = JSONStringOrListField(required=False)
    analysis_purpose = JSONStringOrListField(required=False)

    class Meta:
        model = SampleRequisition
        # user comes from request
        exclude = ('user',)

    def validate(self, attrs):
        # Enforce MSDS file when msds == "Yes"
        msds = attrs.get('msds')
        msds_file = attrs.get('msds_file')
        if msds == 'Yes' and not msds_file:
            raise serializers.ValidationError({'msds_file': 'MSDS file is required when MSDS = Yes.'})
        return attrs

    def create(self, validated_data):
        user = self.context['request'].user

        # Ensure pickup address belongs to the same user (if provided)
        pickup = validated_data.get('pickup_address')
        if pickup and pickup.user_id != user.id:
            raise serializers.ValidationError({'pickup_address': 'Pickup address does not belong to the current user.'})

        validated_data['user'] = user
        return super().create(validated_data)
