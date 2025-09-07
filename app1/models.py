from django.conf import settings
from django.core.validators import MaxLengthValidator, RegexValidator
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class EmailOTP(models.Model):
    email = models.EmailField() #change the email field to user foreign key 
    otp_hash = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=timezone.now() + timezone.timedelta(minutes=5))
    used = models.BooleanField(default=False)

    def is_expired(self):
        return timezone.now() > self.expires_at
 
class CustomUserManager(BaseUserManager):
    def create_user(self, email, full_name, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, full_name=full_name, **extra_fields)
        user.set_password(password)  # hashes the password
        user.save(using=self._db)
        return user

    def create_superuser(self, email, full_name, password=None, **extra_fields):
        extra_fields.setdefault('user_role', 'Admin')
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_staff', True)
        return self.create_user(email, full_name, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    USER_ROLE_CHOICES = [
        ('User', 'User'),
        ('Admin', 'Admin'),
    ]

    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone = models.CharField(
        max_length=10,
        validators=[RegexValidator(regex=r'^\d{10}$', message='Phone number must be 10 digits')],
        blank=True,
        null=True
    )
    # Address fields
    location = models.CharField(max_length=255, blank=True, null=True)
    building_or_room = models.CharField(max_length=255, blank=True, null=True)
    department = models.CharField(max_length=255, blank=True, null=True)
    street_address = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    state_province = models.CharField(max_length=100, blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    # Address fields
    user_role = models.CharField(max_length=5, choices=USER_ROLE_CHOICES, default='User')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Required fields for AbstractBaseUser
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']

    def __str__(self):
        return self.full_name

       

class SampleCollectionAddress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    # Address fields
    location = models.CharField(max_length=255, blank=True, null=True)
    building_or_room = models.CharField(max_length=255, blank=True, null=True)
    department = models.CharField(max_length=255, blank=True, null=True)
    street_address = models.CharField(max_length=255, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    state_province = models.CharField(max_length=100, blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    postal_code = models.CharField(max_length=20, blank=True, null=True)
    preferred_time_slot = models.CharField(max_length=100, blank=True, null=True)
    # New fields
    preferred_date = models.DateField(blank=True, null=True)
    contact_person = models.CharField(max_length=255, blank=True, null=True)
    contact_phone = models.CharField(max_length=20, blank=True, null=True)
    alternate_phone = models.CharField(max_length=20, blank=True, null=True)
    is_business_address = models.BooleanField(default=False)
    pickup_instructions = models.TextField(blank=True, null=True)
    access_notes = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Address for {self.user.full_name}"

    class Meta:
        verbose_name_plural = "Sample Collection Addresses"

# Categories model
class Category(models.Model):
    category_name = models.CharField(max_length=255, unique=True)
    image_url = models.CharField(max_length=255)
    description = models.TextField(validators=[MaxLengthValidator(200)]) 
    info = models.TextField()
    parent_category = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE, related_name='subcategories')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.category_name

    # Method to get the parent category name
    def get_parent_category(self):
        if self.parent_category:
            return self.parent_category.category_name
        return None


# Tests model
class Test(models.Model):
    category = models.ForeignKey(Category, null=True, on_delete=models.CASCADE)
    test_name = models.CharField(max_length=255)
    test_description = models.TextField(validators=[MaxLengthValidator(200)]) 
    image_url = models.CharField(max_length=255)
    test_price = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.test_name


# Labs model
class Lab(models.Model):
    lab_name = models.CharField(max_length=255)
    contact_name = models.CharField(max_length=255, blank=True, null=True)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    address = models.TextField()

    def __str__(self):
        return self.lab_name


# TestAvailability model
class TestAvailability(models.Model):
    test = models.ForeignKey(Test, on_delete=models.CASCADE)
    lab = models.ForeignKey(Lab, on_delete=models.CASCADE)
    STATUS_CHOICES = [
        ('In Stock', 'In Stock'),
        ('Out of Stock', 'Out of Stock'),
        ('Pre-Order', 'Pre-Order'),
        ('Discontinued', 'Discontinued'),
    ]
    test_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='In Stock')
    last_updated = models.DateTimeField(auto_now=True)


# Sessions model
class Session(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    login_time = models.DateTimeField(auto_now_add=True)
    logout_time = models.DateTimeField(null=True, blank=True)


# LoginAttempts model
class LoginAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=50, blank=True, null=True)
    status = models.CharField(max_length=10, choices=[('Success', 'Success'), ('Failure', 'Failure')])
    attempt_time = models.DateTimeField(auto_now_add=True)


# PasswordResets model
class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    reset_token = models.TextField()
    expires_at = models.DateTimeField()
    requested_at = models.DateTimeField(auto_now_add=True)

# Cart model
class Cart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    test = models.ForeignKey(Test, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)


# Orders model
import uuid
class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='orders')
    # Link created requisition (may be added only when form is submitted)
    sample_requisition = models.OneToOneField(
        'SampleRequisition', null=True, blank=True,
        on_delete=models.SET_NULL, related_name='order'
    )
    order_id = models.CharField(max_length=20, unique=True, editable=False, db_index=True)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    order_status = models.CharField(
        max_length=15,
        choices=[
            ('Pending', 'Pending'),
            ('Processing', 'Processing'),
            ('Shipped', 'Shipped'),
            ('Delivered', 'Delivered'),
            ('Cancelled', 'Cancelled')
        ],
        default='Pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def _generate_order_id(self):
        # Format: ORDYYYYMMDDXXXX (date + 4 hex chars)
        today_str = timezone.now().strftime("%Y%m%d")
        suffix = uuid.uuid4().hex[:4].upper()
        return f"ORD{today_str}{suffix}"

    def save(self, *args, **kwargs):
        if not self.order_id:
            for _ in range(5):
                candidate = self._generate_order_id()
                if not Order.objects.filter(order_id=candidate).exists():
                    self.order_id = candidate
                    break
            if not self.order_id:
                self.order_id = f"ORD{uuid.uuid4().hex[:12].upper()}"
        super().save(*args, **kwargs)

    def __str__(self):
        return self.order_id


class OrderSummary(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    test = models.ForeignKey(Test, on_delete=models.CASCADE)
    quantity = models.IntegerField(default=1)
    added_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)

# Purchase model
class PurchaseDetail(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    test = models.ForeignKey(Test, on_delete=models.CASCADE)
    quantity = models.IntegerField()
    price = models.DecimalField(max_digits=10, decimal_places=2)


# Payments model
class Payment(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    payment_method = models.CharField(max_length=20, choices=[('Credit Card', 'Credit Card'),
                                                             ('PayPal', 'PayPal'),
                                                             ('UPI', 'UPI'),
                                                             ('Net Banking', 'Net Banking')])
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_status = models.CharField(max_length=15, choices=[('Pending', 'Pending'), ('Completed', 'Completed'),
                                                              ('Failed', 'Failed'), ('Refunded', 'Refunded')],
                                      default='Pending')
    transaction_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    payment_date = models.DateTimeField(auto_now_add=True)


# InformationForm model
class InformationForm(models.Model):
    information_form_id = models.IntegerField()
    # Add any required fields here

class CustomerSuggestion(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    selected_options = models.JSONField(default=list)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Suggestion by {self.user.email} at {self.created_at}"

class SampleRequisition(models.Model):
    CUSTOMER_TYPES = (
        ("Manufacturing Company", "Manufacturing Company"),
        ("Individual", "Individual"),
    )
    MSDS_CHOICES = (("Yes", "Yes"), ("No", "No"))
    DISPOSAL_CHOICES = (
        ("Discard", "Discard"),
        ("Return", "Return"),
        ("Return unused portion only", "Return unused portion only"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE)

    # Link to the test being ordered (optional if test is not a FK in your DB)
    test_id = models.IntegerField(null=True, blank=True)
    test_name = models.CharField(max_length=255, blank=True)
    quantity = models.PositiveIntegerField(default=1)

    # Section 1
    customer_name = models.CharField(max_length=255)
    customer_type = models.CharField(max_length=64, choices=CUSTOMER_TYPES, default="Manufacturing Company")
    email = models.EmailField()
    phone = models.CharField(max_length=64)
    submission_date = models.DateField()

    # Section 2
    sample_name_or_batch = models.CharField(max_length=255)
    number_of_samples = models.PositiveIntegerField(default=1)
    physical_state = models.CharField(max_length=32)
    appearance = models.CharField(max_length=255, blank=True)
    solubility = models.CharField(max_length=255, blank=True)
    special_handling = models.CharField(max_length=255, blank=True)
    usage = models.CharField(max_length=255, blank=True)
    storage_conditions = models.JSONField(default=list, blank=True)
    storage_other = models.CharField(max_length=255, blank=True)
    hazard_info = models.JSONField(default=list, blank=True)
    msds = models.CharField(max_length=8, choices=MSDS_CHOICES, default="No")
    msds_file = models.FileField(upload_to="msds/", null=True, blank=True)

    # Section 3
    requested_technique = models.CharField(max_length=255)
    analysis_purpose = models.JSONField(default=list, blank=True)
    amount_provided = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    amount_unit = models.CharField(max_length=16, default="mg")
    requested_tat = models.CharField(max_length=64, default="Standard (5–7 days)")
    client_sample_code = models.CharField(max_length=255, blank=True)

    # Section 4
    notes = models.TextField(blank=True)
    sample_disposal = models.CharField(max_length=64, choices=DISPOSAL_CHOICES, default="Discard")
    return_shipping_address = models.TextField(blank=True)

    # Section 5
    declaration_accepted = models.BooleanField(default=False)
    signature = models.CharField(max_length=255, blank=True)
    authorization_date = models.DateField()

    # Pickup link (reuses your existing address model)
    pickup_address = models.ForeignKey("SampleCollectionAddress", on_delete=models.SET_NULL, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Requisition #{self.id} - {self.customer_name}"