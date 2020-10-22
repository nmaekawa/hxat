# Generated by Django 2.1.7 on 2019-04-16 21:09

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Annotation",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("context_id", models.CharField(db_index=True, max_length=1024)),
                ("collection_id", models.CharField(max_length=1024)),
                ("uri", models.CharField(max_length=2048)),
                ("media", models.CharField(max_length=24)),
                ("user_id", models.CharField(max_length=1024)),
                ("user_name", models.CharField(max_length=1024)),
                ("is_private", models.BooleanField(default=False)),
                ("is_deleted", models.BooleanField(default=False)),
                ("text", models.TextField(blank=True, default="")),
                ("quote", models.TextField(blank=True, default="")),
                ("json", models.TextField(blank=True, default="{}")),
                ("total_comments", models.PositiveIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "parent",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to="annotation_store.Annotation",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="AnnotationTags",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=128, unique=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
        ),
        migrations.AddField(
            model_name="annotation",
            name="tags",
            field=models.ManyToManyField(
                related_name="annotations", to="annotation_store.AnnotationTags"
            ),
        ),
    ]
