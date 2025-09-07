from django.contrib import admin
from .models import SampleRequisition, User, Category, Test, Lab, TestAvailability, Session, LoginAttempt, PasswordReset, Cart,OrderSummary, Order, PurchaseDetail, Payment, InformationForm, EmailOTP
from django.contrib import admin

class UserAdmin(admin.ModelAdmin):
    # Fields to display in the list view
    list_display = ('id', 'full_name', 'email', 'phone', 
                   'user_role', 'created_at', 'updated_at')
    
    # Make the fields clickable for editing
    list_display_links = ('id', 'full_name', 'email')
    
    # Add search functionality
    search_fields = ('full_name', 'email', 'phone')
    
    # Add filters for these fields
    list_filter = ('user_role', 'created_at', 'updated_at')
    
    # Fields to show in the detail/edit view
    fieldsets = (
        (None, {'fields': ('full_name', 'email', 'password')}),
        ('Contact Information', {
            'fields': (
                'phone','location', 'building_or_room', 'department',
                'street_address', 'city', 'state_province', 'region', 'postal_code'
            )
        }),
        ('Metadata', {
            'fields': ('user_role', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    # Make created_at and updated_at read-only
    readonly_fields = ('created_at', 'updated_at')

admin.site.register(User, UserAdmin)

class CategoryAdmin(admin.ModelAdmin):
    list_display = ('id', 'category_name', 'image_url', 'description', 'info', 'parent_category_id', 'created_at', 'updated_at')
    search_fields = ('category_name',)
    list_filter = ('parent_category_id',)

    # Add this method to display parent category's ID in the admin list view
    def parent_category_id(self, obj):
        return obj.parent_category.id if obj.parent_category else None
    parent_category_id.short_description = 'Parent category ID'

admin.site.register(Category, CategoryAdmin)

class TestAdmin(admin.ModelAdmin):
    list_display = ('id', 'test_name', 'category_id_display', 'test_description', 'image_url', 'test_price', 'created_at', 'updated_at')
    search_fields = ('test_name',)
    list_filter = ('category',)

    def category_id_display(self, obj):
        return obj.category.id
    category_id_display.short_description = 'Category ID'

admin.site.register(Test, TestAdmin)

class EmailOTPAdmin(admin.ModelAdmin):
    list_display = ('email', 'created_at', 'expires_at', 'used')
    list_filter = ('used', 'created_at', 'expires_at')
    search_fields = ('email',)
    ordering = ('-created_at',)
admin.site.register(EmailOTP)

admin.site.register(Lab)
admin.site.register(TestAvailability)
admin.site.register(Session)
admin.site.register(LoginAttempt)
admin.site.register(PasswordReset)

class CartAdmin(admin.ModelAdmin):
    list_display = ('id', 'get_user_info', 'get_test_name', 'quantity', 'added_at', 'expires_at')
    list_filter = ('added_at', 'expires_at', 'user__user_role')
    search_fields = ('user__full_name', 'user__email', 'test__test_name')
    ordering = ('-added_at',)
    list_select_related = ('user', 'test')  # For better performance
    
    def get_user_info(self, obj):
        return f"{obj.user.full_name} ({obj.user.email}) - {obj.user.user_role}"
    get_user_info.short_description = 'User Info'
    get_user_info.admin_order_field = 'user__full_name'
    
    def get_test_name(self, obj):
        return f"{obj.test.test_name} (ID: {obj.test.id})"
    get_test_name.short_description = 'Test'
    get_test_name.admin_order_field = 'test__test_name'

admin.site.register(Cart, CartAdmin)

class OrderSummaryAdmin(admin.ModelAdmin):
    list_display = ('id', 'get_user_info', 'get_test_name', 'quantity', 'added_at', 'expires_at')
    list_filter = ('added_at', 'expires_at', 'user__user_role')
    search_fields = ('user__full_name', 'user__email', 'test__test_name')
    ordering = ('-added_at',)
    list_select_related = ('user', 'test')  # For better performance
    
    def get_user_info(self, obj):
        return f"{obj.user.full_name} ({obj.user.email}) - {obj.user.user_role}"
    get_user_info.short_description = 'User Info'
    get_user_info.admin_order_field = 'user__full_name'
    
    def get_test_name(self, obj):
        return f"{obj.test.test_name} (ID: {obj.test.id})"
    get_test_name.short_description = 'Test'
    get_test_name.admin_order_field = 'test__test_name'

admin.site.register(OrderSummary, OrderSummaryAdmin)

from .models import Order
class OrderAdmin(admin.ModelAdmin):
    list_display = ('order_id', 'user', 'sample_requisition', 'total_amount', 'order_status', 'created_at')
    search_fields = ('order_id', 'user__email')
    list_filter = ('order_status', 'created_at')
admin.site.unregister(Order) if 'Order' in admin.site._registry else None
admin.site.register(Order, OrderAdmin)

admin.site.register(PurchaseDetail)
admin.site.register(Payment)
admin.site.register(InformationForm)

from .models import SampleCollectionAddress

class SampleCollectionAddressAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'user_id', 'user_full_name', 'location', 'building_or_room', 'department',
        'street_address', 'city', 'state_province', 'region', 'postal_code','preferred_time_slot',
        'created_at', 'updated_at'
    )
    search_fields = ('user__full_name', 'user__email', 'city', 'street_address', 'postal_code')
    list_filter = ('city', 'state_province', 'created_at', 'updated_at')

    def user_full_name(self, obj):
        return obj.user.full_name
    user_full_name.short_description = 'User Name'

admin.site.register(SampleCollectionAddress, SampleCollectionAddressAdmin)

from .models import CustomerSuggestion
class CustomerSuggestionAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'selected_options', 'message', 'created_at')
    search_fields = ('user__email', 'message')
    list_filter = ('created_at',)
admin.site.register(CustomerSuggestion, CustomerSuggestionAdmin)

admin.site.register(SampleRequisition)
