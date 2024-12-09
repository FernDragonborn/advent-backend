# Generated by Django 5.1.3 on 2024-11-29 16:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("advent_app", "0002_alter_user_name"),
    ]

    operations = [
        migrations.AlterField(
            model_name="emailverification",
            name="verification_code",
            field=models.CharField(max_length=6),
        ),
        migrations.AlterField(
            model_name="user",
            name="gender",
            field=models.CharField(
                blank=True,
                choices=[("M", "Чоловік"), ("F", "Жінка"), ("U", "Не хочу говорити")],
                max_length=1,
                null=True,
                verbose_name="Стать",
            ),
        ),
    ]