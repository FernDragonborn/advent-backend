# Generated by Django 5.1.3 on 2024-12-04 20:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("advent_app", "0004_alter_emailverification_verification_code"),
    ]

    operations = [
        migrations.AddField(
            model_name="task",
            name="task_image_1_mob",
            field=models.ImageField(null=True, upload_to=""),
        ),
        migrations.AddField(
            model_name="task",
            name="task_image_2_mob",
            field=models.ImageField(null=True, upload_to=""),
        ),
        migrations.AddField(
            model_name="task",
            name="task_image_3_mob",
            field=models.ImageField(null=True, upload_to=""),
        ),
    ]
