from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.crypto import get_random_string


class User(AbstractUser):
    region = models.CharField(max_length=255, null=True, blank=True)
    grade = models.CharField(max_length=50, null=True, blank=True)
    phone_number = models.CharField(max_length=20, null=True, blank=True)
    name = models.CharField(
        max_length=150,
        unique=False,
    )

    class Gender(models.TextChoices):
        MALE = 'M', 'Чоловік'
        FEMALE = 'F', 'Жінка'
        UNDEFINED = 'U', 'Не хочу говорити'
        #OTHER = 'O', 'Інше'

    gender = models.CharField(
        max_length=1,
        choices=Gender.choices,
        null=True,
        blank=True,
        verbose_name="Стать"
    )

    email = models.EmailField(unique=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    @property
    def group(self):
        group = None
        if self.grade and int(self.grade) < 7:
            group = 1
        elif self.grade and int(self.grade) > 8:
            group = 3
        else:
            group = 2
        return group


class TaskGroups(models.TextChoices):
    FIRST = "First group"
    SECOND = "Second group"
    THIRD = "Third group"

class Task(models.Model):
    group = models.CharField(choices=TaskGroups.choices, default=TaskGroups.FIRST, max_length=255)
    due_date = models.DateTimeField()
    video_link = models.TextField(null=True, blank=True)
    intro_text = models.TextField(null=True)
    outro_text = models.TextField(null=True)
    fail_text = models.TextField(null=True)
    intro_image = models.ImageField(null=True)
    teleport_image = models.ImageField(null=True)
    task_image_1 = models.ImageField(null=True)
    task_image_2 = models.ImageField(null=True, blank=True)
    task_image_3 = models.ImageField(null=True, blank=True)
    task_image_1_mob = models.ImageField(null=True)
    task_image_2_mob = models.ImageField(null=True, blank=True)
    task_image_3_mob = models.ImageField(null=True, blank=True)
    correct_answer_1 = models.CharField(max_length=255)
    correct_answer_2 = models.CharField(max_length=255)
    correct_answer_3 = models.CharField(max_length=255)
    unlocks_artifact = models.BooleanField(default=False)
    points_award = models.SmallIntegerField(default=5, null=False)
    
    def __str__(self):
        return f"{self.due_date} {self.group})"


class TaskResponse(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="response")
    created_at = models.DateTimeField(auto_now_add=True)
    recorded_answer = models.TextField(null=True)
    is_correct = models.BooleanField(default=True)

class EmailVerification(models.Model):
    """
    Model to store email verification codes
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    verification_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def generate_verification_code(self) -> str:
        """
        Generate a unique 6-digit verification code
        """
        self.verification_code = get_random_string(length=6, allowed_chars='0123456789')
        self.save()
        return self.verification_code
