from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    address = models.CharField(max_length=255, null=False)
    full_name = models.CharField(max_length=255, null=False)
    region = models.CharField(max_length=255, null=True, blank=True)
    grade = models.CharField(max_length=50, null=True, blank=True)

    @property
    def group(self):
        group = None
        if self.grade < 7:
            group = 1
        elif self.grade > 8:
            group = 3
        else:
            group = 2
        return group
    
class TaskGroups(models.IntegerChoices):
    FIRST = 1, "First group"
    SECOND = 2, "Second group"
    THIRD = 3, "Third group"

class Task(models.Model):
    group = models.SmallIntegerField(choices=TaskGroups)
    due_date = models.DateTimeField()
    intro_text = models.TextField(null=True)
    outro_text = models.TextField(null=True)
    task_test = models.TextField(null=True)
    task_image_1 = models.ImageField(null=True)
    task_image_2 = models.ImageField(null=True)
    task_image_3 = models.ImageField(null=True)
    correct_answer_1 = models.CharField(max_length=255)
    correct_answer_2 = models.CharField(max_length=255)
    correct_answer_3 = models.CharField(max_length=255)
    unlocks_artifact = models.BooleanField(default=False)
    points_award = models.SmallIntegerField(default=5, null=False)



class TaskResponse(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="response")
    recorded_answer = models.TextField(null=True)
    is_correct = models.BooleanField(default=True)