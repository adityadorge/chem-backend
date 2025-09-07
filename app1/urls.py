from django.urls import path
from . import views
# from .views import CategoryListView, TestListView

app_name = "app1"
urlpatterns = [
    path("", views.index, name="index"),

    path('exchange-token/', views.exchange_token, name='exchange_token'),
    path('verify-token/', views.VerifyToken.as_view(), name='verify_token'),    

    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path('logout/', views.logout_view, name='logout'),
    path("protected/", views.protected_view, name="protected"),
    path("profile/", views.ProfileView.as_view(), name="profile"),

    path('categories/', views.CategoryListView.as_view(), name='category-list'),
    path('categories/<int:category_id>/subcategories/', views.SubcategoryListView.as_view(), name='subcategory-list'),

    path('tests/<int:test_id>/', views.SingleTestDetailView.as_view(), name='test-detail'),
    path('categories/<int:category_id>/tests/', views.TestByCategoryView.as_view(), name='tests-by-category'),

    path('add-to-cart/', views.AddToCartView.as_view(), name='add-to-cart'),
    path('add-cart-to-ordersummary/', views.AddCartToOrderSummaryView.as_view(), name='cart-to-ordersummary'),
    path('cart/', views.FetchCartDetailView.as_view(), name='get-cart'),
    path('cart/delete/<int:item_id>/', views.delete_cart_item, name='delete-cart-item'),
    path('cart/update/', views.update_cart_item, name='update-cart-item'),

    path("send-otp/", views.SendOTPView.as_view(),name='send-otp'),
    path("verify-otp/", views.VerifyOTPView.as_view(),name='verify-otp'),

    path('auth/send-password-reset-link/', views.SendPasswordResetEmailView.as_view()),
    path('auth/reset-password/<uidb64>/<token>/', views.ResetPasswordView.as_view()),

    path("save-address/", views.SaveAddressView.as_view(), name='save-address'),
    path('get-address/', views.GetAddressView.as_view(), name='get-address'),

    path('add-to-ordersummary/', views.AddToOrderSummaryView.as_view(), name='add-to-ordersummary'),
    path('get-ordersummary/', views.GetOrderSummaryView.as_view(), name='get-ordersummary'),
    path('delete-ordersummary-item/<int:item_id>/', views.delete_order_summary_item, name='delete-ordersummary-item'),
    path('update-ordersummary-item/', views.update_order_summary_item, name='update-ordersummary-item'),

    path('suggestions/', views.SuggestionView.as_view(), name='suggestions'),

    path('sample-requisitions/', views.SampleRequisitionCreateView.as_view(), name='sample-requisitions-create'),

]