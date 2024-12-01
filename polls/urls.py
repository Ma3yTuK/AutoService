from django.urls import path
from . import views

app_name = "polls"
urlpatterns = [
    path("vehicles", views.VehiclesView.as_view(template_name="polls/vehicles.html"), name="vehicles"),
    path("rent/<int:id>", views.CreateRentView.as_view(), name="rent"),
    path("end_rent/<int:id>", views.EndRentView.as_view(), name="end_rent"),
    path("cart", views.CartView.as_view(template_name="polls/cart.html"), name="cart"),
    path("reviews", views.ReviewsView.as_view(template_name="polls/reviews.html"), name="reviews"),
    path("review", views.ReviewCreateView.as_view(template_name="polls/review.html"), name="review"),
    path("journal", views.JournalView.as_view(template_name="polls/journal.html"), name="journal"),
]
