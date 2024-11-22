from rest_framework import serializers
from advent_app.models import User, Task, TaskResponse

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User

class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task

class TaskResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskResponse

class StudentRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password', 'email', 'region', 'grade']

    def validate(self, data):
        if not data.get('region'):
            raise serializers.ValidationError("Поле 'region' є обов'язковим для школярів.")
        if not data.get('grade'):
            raise serializers.ValidationError("Поле 'grade' є обов'язковим для школярів.")
        return data

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            region=validated_data['region'],
            grade=validated_data['grade'],
        )
        return user