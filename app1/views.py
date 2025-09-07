# Create your views here.
import requests
import json
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from .serializers import RegisterSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .models import Category, Test, User, Cart, CustomerSuggestion
from .serializers import CategorySerializer, TestSerializer, CartSerializer, SendOTPSerializer, VerifyOTPSerializer, SuggestionSerializer
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model, logout
from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import logout
User = get_user_model()


def index(request):
    return HttpResponse("Hello, world. You're at the polls index.")


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def protected_view(request):
    print(" iam inside  protected_view")
    return Response({"message": "This is a protected view!"}, status=status.HTTP_200_OK)


# Generate JWT tokens
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@permission_classes([IsAuthenticated])
class ProfileView(APIView):

    def get(self, request):
        print("i am indisde ProfileView")
        user = User.objects.get(id=request.user.id)
        print(user)
        return Response({
            "id": user.id,
            "name": user.full_name,
            "email": user.email,
        })
        

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            print("i am inside RegisterView 2")
            user = serializer.save()
            return Response({
                "message": "User registered successfully",
            }, status=status.HTTP_201_CREATED)
        print("Serializer errors:", serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        print("hello i am inside view")
        data = request.data
        email = data.get("email")
        print(email)
        password = data.get("password")
        print(password)

        try:
            user = User.objects.get(email=email)
            print(user.check_password(password))
            if user.check_password(password):
                tokens = get_tokens_for_user(user)
                print({"tokens": tokens, "user": {
                      "full_name": user.full_name, "email": user.email}})
                return Response({"tokens": tokens, "user": {"full_name": user.full_name, "email": user.email}}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class CategoryListView(APIView):
    def get(self, request):
        # Fetch only categories with no parent
        categories = Category.objects.filter(parent_category__isnull=True)
        serializer = CategorySerializer(categories, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class SubcategoryListView(APIView):
    def get(self, request, category_id):
        # Fetch subcategories of a particular category
        category = Category.objects.get(id=category_id)
        # Assuming there's a relationship in the model
        subcategories = category.subcategories.all()
        serializer = CategorySerializer(subcategories, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class SingleTestDetailView(APIView):
    def get(self, request, test_id):
        test = Test.objects.get(id=test_id)
        serializer = TestSerializer(test)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TestListView(APIView):
    def get(self, request):
        tests = Test.objects.all()
        serializer = TestSerializer(tests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TestByCategoryView(APIView):
    def get(self, request, category_id):
        tests = Test.objects.filter(category__id=category_id)
        serializer = TestSerializer(tests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
"""############################################### START : CartView ###############################################""" 
@permission_classes([IsAuthenticated])
class AddToCartView(APIView):

    def post(self, request):
        print("Inside AddToCartView")
        print("Auth User:", request.user)

        try:
            data = request.data
            print("Raw data:", data)

            test_id = data.get('test_id')
            quantity = int(data.get('quantity', 1))

            print("Parsed test_id:", test_id)
            print("Parsed quantity:", quantity)

            if not test_id or quantity < 1:
                return Response({'status': 'error', 'message': 'Invalid input'}, status=400)

            if quantity > 10:
                return Response({'status': 'error', 'message': 'Max 10 items allowed'}, status=400)

            user = User.objects.get(id=request.user.id)
            test = Test.objects.get(id=test_id)

            cart_item, created = Cart.objects.get_or_create(
                user=user,
                test=test,
                defaults={
                    'quantity': quantity,
                    'expires_at': timezone.now() + timedelta(days=30)
                }
            )

            if not created:
                cart_item.quantity += quantity
                cart_item.save()

            return Response({
                'status': 'success',
                'message': 'Item added to cart',
                'cart_item': {
                    'id': cart_item.id,
                    'test_name': test.test_name,
                    'test_id': test.id,
                    'quantity': cart_item.quantity,
                    'added_at': cart_item.added_at
                }
            }, status=status.HTTP_201_CREATED)

        except Test.DoesNotExist:
            return Response({'status': 'error', 'message': 'Test not found'}, status=404)

        except ValueError as e:
            print("ValueError occurred:", e)
            return Response({'status': 'error', 'message': 'Invalid quantity or test ID'}, status=400)

        except Exception as e:
            print("Unexpected Exception:", str(e))
            return Response({'status': 'error', 'message': str(e)}, status=400)

@permission_classes([IsAuthenticated])
class FetchCartDetailView(APIView):

    def get(self, request):

        if not request.user.is_authenticated:
            return Response({"error": "User is not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Replace with request.user.id
            user_instance = User.objects.get(id=request.user.id)
            cart_items = Cart.objects.filter(user=user_instance)
            serializer = CartSerializer(cart_items, many=True)

            print(serializer.data)

            return Response({"cart": serializer.data}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def update_cart_item(request):
    user = request.user
    cart_id = request.data.get("cart_id")
    quantity = request.data.get("quantity")

    if not cart_id or not quantity:
        return Response({"error": "Invalid data"}, status=400)

    try:
        cart_item = Cart.objects.get(id=cart_id,user=user)
        cart_item.quantity = quantity
        cart_item.save()
        return Response({"status": "success"})
    except Cart.DoesNotExist:
        return Response({"error": "Item not in cart"}, status=404)
    

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_cart_item(request, item_id):
    try:
        item = Cart.objects.get(id=item_id, user=request.user)
        item.delete()
        return Response({'status': 'success', 'message': 'Item removed from cart'})
    except Cart.DoesNotExist:
        return Response({'status': 'error', 'message': 'Item not found'}, status=404)



from django.utils import timezone
from datetime import timedelta

class AddCartToOrderSummaryView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        cart_items = Cart.objects.filter(user=user)
        if not cart_items.exists():
            return Response({'status': 'error', 'message': 'Cart is empty'}, status=400)

        for cart_item in cart_items:
            # Check if this test is already in OrderSummary for this user
            order_item, created = OrderSummary.objects.get_or_create(
                user=user,
                test=cart_item.test,
                defaults={
                    'quantity': cart_item.quantity,
                    'expires_at': timezone.now() + timedelta(days=30)
                }
            )
            if not created:
                order_item.quantity += cart_item.quantity
                order_item.save()
            # Optionally, you can copy other fields if needed

        return Response({'status': 'success', 'message': 'Cart moved to order summary.'}, status=201)

"""############################################### END : CartView ###############################################"""        

"""############################################### START : AddToOrderSummaryView ###############################################"""
from .models import OrderSummary
class AddToOrderSummaryView(APIView):

    def post(self, request):
        print("Inside AddToOrderSummaryView")
        print("Auth User:", request.user)

        try:
            data = request.data
            print("Raw data:", data)

            test_id = data.get('test_id')
            quantity = int(data.get('quantity', 1))

            print("Parsed test_id:", test_id)
            print("Parsed quantity:", quantity)

            if not test_id or quantity < 1:
                return Response({'status': 'error', 'message': 'Invalid input'}, status=400)

            if quantity > 10:
                return Response({'status': 'error', 'message': 'Max 10 items allowed'}, status=400)

            user = User.objects.get(id=request.user.id)
            test = Test.objects.get(id=test_id)

            OrderSummary_item, created = OrderSummary.objects.get_or_create(
                user=user,
                test=test,
                defaults={
                    'quantity': quantity,
                    'expires_at': timezone.now() + timedelta(days=30)
                }
            )

            if not created:
                OrderSummary_item.quantity += quantity
                OrderSummary_item.save()

            return Response({
                'status': 'success',
                'message': 'Item added to Order Summary',
                'OrderSummary_item': {
                    'id': OrderSummary_item.id,
                    'test_name': test.test_name,
                    'test_id': test.id,
                    'quantity': OrderSummary_item.quantity,
                    'added_at': OrderSummary_item.added_at
                }
            }, status=status.HTTP_201_CREATED)

        except Test.DoesNotExist:
            return Response({'status': 'error', 'message': 'Test not found'}, status=404)

        except ValueError as e:
            print("ValueError occurred:", e)
            return Response({'status': 'error', 'message': 'Invalid quantity or test ID'}, status=400)

        except Exception as e:
            print("Unexpected Exception:", str(e))
            return Response({'status': 'error', 'message': str(e)}, status=400)

from .serializers import OrderSummarySerializer
@permission_classes([IsAuthenticated])
class GetOrderSummaryView(APIView):

    def get(self, request):

        if not request.user.is_authenticated:
            return Response({"error": "User is not authenticated"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            # Replace with request.user.id
            user_instance = User.objects.get(id=request.user.id)
            OrderSummary_items = OrderSummary.objects.filter(user=user_instance)
            serializer = OrderSummarySerializer(OrderSummary_items, many=True)

            print(serializer.data)

            return Response({"OrderSummary": serializer.data}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(["PATCH"])
@permission_classes([IsAuthenticated])
def update_order_summary_item(request):
    user = request.user
    item_id = request.data.get("item_id")
    quantity = request.data.get("quantity")

    if not item_id or not quantity:
        return Response({"error": "Invalid data"}, status=400)

    try:
        order_item = OrderSummary.objects.get(id=item_id, user=user)
        order_item.quantity = quantity
        order_item.save()
        return Response({"status": "success"})
    except OrderSummary.DoesNotExist:
        return Response({"error": "Item not in order summary"}, status=404)

@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_order_summary_item(request, item_id):
    try:
        item = OrderSummary.objects.get(id=item_id, user=request.user)
        item.delete()
        return Response({'status': 'success', 'message': 'Item removed from order summary'})
    except OrderSummary.DoesNotExist:
        return Response({'status': 'error', 'message': 'Item not found'}, status=404)

"""############################################### END : AddToOrderSummaryView ###############################################"""

@api_view(['POST'])
@permission_classes([AllowAny]) # because the user is not logged yet.
def exchange_token(request):
    """
    Exchanges a Google ID token for a Django REST Framework authentication token.

    This view handles the exchange of a Google ID token (obtained from the client-side Google Sign-In flow) for a Django REST Framework
    authentication token. It performs the following steps:

    1. Verifies the Google ID token by making a request to the Google OAuth2 tokeninfo API.
    2. Extracts the user's email, name, and Google user ID from the token info.
    3. Gets or creates a Django user based on the email address.
    4. Generates or retrieves the user's Django REST Framework authentication token.
    5. Returns the user information and the authentication token, setting the token as an HTTP-only cookie.

    """
    # Get the 'credential' JWT sended by the frontend
    credential = request.data.get('credential')

    if not credential:
        return JsonResponse({'error': 'Credential is required'}, status=400)

    try:
        # Verify the ID token
        token_info_url = f'https://oauth2.googleapis.com/tokeninfo?id_token={credential}'
        token_info_response = requests.get(token_info_url)
        # print("token_info_response",token_info_response)
        token_info = token_info_response.json()

        if 'error_description' in token_info:
            return JsonResponse({'error': 'Invalid ID token'}, status=400)

        # Extract user info
        email = token_info.get('email')  
        name = token_info.get('name')
        google_user_id = token_info.get('sub')
        # Get or create user !!!! Change later !!!
        try:
            print("Trying to get or create user...")
            user, created = User.objects.get_or_create(
                email=email,
                defaults={'full_name': name}
            )
        except Exception as e:
            print("Error while creating user:", str(e))
        
        # Generate or get the token
        tokens = get_tokens_for_user(user=user)
        print(tokens)
        access_token = tokens["access"]
        refresh_token = tokens["refresh"]

        # Prepare user info to return
        user_info = {
            'id': user.id,
            'email': user.email,
            'name': user.full_name,
        }
        
        response = JsonResponse({
            "tokens": tokens,
            'user': user_info
        })
        
        
        # Set the auth token as an HTTP-only cookie
        response.set_cookie(
            key='access',
            value=access_token,
            httponly=True,
            secure=False,  # Use TRUE in production with HTTPS
            samesite='Lax',
            max_age=3600 * 24 * 30,  # 30 days
            domain=settings.SESSION_COOKIE_DOMAIN,
            path=settings.SESSION_COOKIE_PATH,
        )
        response.set_cookie(
            key='refresh',
            value=refresh_token,
            httponly=True,
            secure=False,  # Use TRUE in production with HTTPS
            samesite='Lax',
            max_age=3600 * 24 * 30,  # 30 days
            domain=settings.SESSION_COOKIE_DOMAIN,
            path=settings.SESSION_COOKIE_PATH,
        )
        
        return response

    except Exception as e:
        return JsonResponse({'error': 'Failed to verify ID token'}, status=400)


@permission_classes([IsAuthenticated])
class VerifyToken(generics.ListAPIView):
    print("inside VerifyToken")
    """
    This view provides a simple endpoint to verify that the access token generated by the authentication system is valid.
    When a client makes a GET request to this endpoint, the view will return a JSON response with a "message" field
    indicating that the token is valid.
    """
    authentication_classes = [TokenAuthentication]

    def get(self, request, *args, **kwargs):
        response = {
            'message': 'The Token is valid and the user is logged in.',
            'isAuhtenticated': request.user.is_authenticated,
            'user': {
                'id': request.user.id,
                'email': request.user.email,
                'name': request.user.get_full_name() or request.user.username,
            }
        }
        print(response)
        return Response(response, status=200)

@api_view(['POST'])
def logout_view(request):
    """
    Logs out the user and clears JWT cookies.
    """
    if request.user.is_authenticated:
        logout(request)  # Optional: Clears Django session if used

    response = Response({"detail": "Successfully logged out."})

    # ✅ Delete JWT cookies
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')

    return response


from .models import EmailOTP
from .utils import generate_otp, hash_otp, send_otp_email #, is_expired

class SendOTPView(APIView):
    print(" i am inside SendOTPView")
    def post(self, request):
        serializer = SendOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({"success": False, "error": serializer.errors}, status=400)

        email = serializer.validated_data["email"]

        otp = generate_otp()
        hashed = hash_otp(otp)
        EmailOTP.objects.update_or_create(email=email, defaults={"otp_hash": hashed})
        send_otp_email(email, otp)

        return Response({"success": True, "message": "OTP sent successfully"}, status=200)

import logging
class VerifyOTPView(APIView):
    print("I am inside VerifyOTPView")
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        user_data = serializer.validated_data["userData"]
        otp = serializer.validated_data["otp"]

        email = user_data.get("email")
        full_name = user_data.get("full_name")
        password = user_data.get("password")
        
        try:
            otp_instance = EmailOTP.objects.get(email=email)
        except EmailOTP.DoesNotExist:
            return Response({"error": "OTP not found"}, status=404)

        if hash_otp(otp) != otp_instance.otp_hash:
            return Response({"error": "Invalid OTP"}, status=400)


        otp_instance.used = True
        otp_instance.save()

        user = User.objects.create_user(
            email=email,
            full_name=full_name,
            password=password
        )
        user.save()

        otp_instance.delete()

        return Response({
    "message": "OTP verified!",
    "user": {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name
    }
})




# views.py
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from .forms import SetNewPasswordForm

class SendPasswordResetEmailView(APIView):
    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=404)

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)
        current_site = get_current_site(request).domain
        reset_url = f"http://{current_site}/auth/reset-password/{uid}/{token}/"

        send_mail(
            subject="Password Reset Request",
            message=f"Click the link to reset your password (valid for 5 minutes): {reset_url}",
            from_email="adityadorge07@gmail.com",
            recipient_list=[email],
        )

        # 🟡 Just print the link to the console instead of sending an email
        print(f"🔗 Password reset link for testing: {reset_url}")

        return Response({"success": True, "message": "Password reset link sent to email."},status=200)


class ResetPasswordView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)

            if not PasswordResetTokenGenerator().check_token(user, token):
                print("i am inside PasswordResetTokenGenerator" )
                return render(request, "app1/password_reset_invalid.html")

            form = SetNewPasswordForm()
            return render(request, "app1/password_reset_form.html", {"form": form, "uidb64": uidb64, "token": token})

        except Exception as e:
            return render(request, "app1/password_reset_invalid.html")

    def post(self, request, uidb64, token):
        form = SetNewPasswordForm(request.POST)
        if form.is_valid():
            try:
                uid = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=uid)

                if not PasswordResetTokenGenerator().check_token(user, token):
                    return render(request, "app1/password_reset_invalid.html")

                password = form.cleaned_data['password']
                user.set_password(password)
                user.save()
                return render(request, "app1/password_reset_success.html")

            except Exception:
                return render(request, "app1/password_reset_invalid.html")

        return render(request, "app1/password_reset_form.html", {"form": form, "uidb64": uidb64, "token": token})

from rest_framework.permissions import IsAuthenticated
from .serializers import SampleCollectionAddressSerializer
from .models import SampleCollectionAddress

TIME_SLOT_CHOICES = [
    ("9:00 AM - 12:00 PM", "morning"),
    ("12:00 PM - 3:00 PM", "afternoon"),
    ("3:00 PM - 6:00 PM", "evening"),
]

class GetAddressView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        address = SampleCollectionAddress.objects.filter(user=user).order_by('-created_at').first()
        if address:
            serializer = SampleCollectionAddressSerializer(address)
            address_data = serializer.data
        else:
            address_data = {}
        
        # Prepare time slots as a list of dicts for frontend

        time_slots = [{"value": v, "label": l} for v, l in TIME_SLOT_CHOICES]

        return Response({
            "address": address_data,
            "time_slots": time_slots
        })
    
class SaveAddressView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = SampleCollectionAddressSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        obj, _created = SampleCollectionAddress.objects.update_or_create(
            user=request.user,
            defaults=serializer.validated_data
        )
        return Response(SampleCollectionAddressSerializer(obj).data, status=status.HTTP_200_OK)

### Suggestion View
class SuggestionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = SuggestionSerializer(data=request.data)
        if serializer.is_valid():
            suggestion = CustomerSuggestion.objects.create(
                user=request.user,
                selected_options=serializer.validated_data['selected_options'],
                message=serializer.validated_data['message']
            )
            # Format email content
            subject = "New Suggestion from {}".format(request.user.email)
            selected = "\n".join(suggestion.selected_options)
            body = f"""
            📬 *New Customer Suggestion Received*

            ----------------------------------------
            👤 Submitted By: {request.user.email}
            🕒 Submitted At: {suggestion.created_at.strftime('%Y-%m-%d %H:%M:%S')}
            ----------------------------------------

            📝 *Selected Options:*
            {selected or "None"}

            💬 *Custom Message:*
            {suggestion.message or "No message provided."}

            ----------------------------------------
            """
            # Send the email to CEO
            send_mail(
                subject,
                body,
                settings.DEFAULT_FROM_EMAIL,
                ['adityadorge07@gmail.com'],
                fail_silently=False
            )

            return Response({"message": "Suggestion saved!"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Add import
from .serializers import SampleRequisitionSerializer
from .models import SampleCollectionAddress, SampleRequisition
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.db import transaction
from decimal import Decimal
from .models import SampleRequisition, Order, Test

class SampleRequisitionCreateView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        serializer = SampleRequisitionSerializer(data=request.data, context={'request': request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        with transaction.atomic():
            requisition = serializer.save()

            # Derive total amount (if test_id present and valid)
            total_amount = Decimal('0.00')
            test_id = requisition.test_id
            qty = requisition.quantity or 1
            if test_id:
                test_obj = Test.objects.filter(id=test_id).first()
                if test_obj:
                    total_amount = (test_obj.test_price or Decimal('0')) * qty

            order = Order.objects.create(
                user=request.user,
                sample_requisition=requisition,
                total_amount=total_amount,
                order_status='Pending'
            )

        return Response({
            'requisition_id': requisition.id,
            'order_id': order.order_id,
            'order_status': order.order_status,
            'total_amount': str(order.total_amount)
        }, status=status.HTTP_201_CREATED)
