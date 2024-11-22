from advent_app.serializers import UserSerializer, TaskSerializer, TaskResponseSerializer
from rest_framework import generics
from advent_app.models import User, Task, TaskResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from oauth2_provider.contrib.rest_framework import TokenHasReadWriteScope, OAuth2Authentication
from rest_framework.permissions import IsAuthenticated


class TaskListView(generics.ListAPIView):
    serialzer_class = TaskSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        group = self.request.user.group
        return Task.objects.filter(group=group)
    
class TaskResponseListCreateView(generics.ListCreateAPIView):
    serializer_class = TaskResponseSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        return TaskResponse.objects.filter(user=self.request.user)

class HelloWorldView(APIView):
    authentication_classes = [OAuth2Authentication]
    permission_classes = [IsAuthenticated, TokenHasReadWriteScope]

    def get(self, request):
        return Response({'message': 'Привіт, світ!'})